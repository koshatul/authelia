package storage

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/authelia/authelia/internal/authentication"
	"github.com/authelia/authelia/internal/configuration/schema"
	"github.com/authelia/authelia/internal/logging"
	"github.com/authelia/authelia/internal/models"
	"github.com/go-ldap/ldap/v3"
)

type ldapStorageProfile struct {
	DN       string
	Username string
	Method   string
	Secret   string
}

type ldapU2FDeviceHandle struct {
	keyHandle []byte
	publicKey []byte
}

// LDAPProvider is a SQLite3 provider.
type LDAPProvider struct {
	configuration schema.LDAPStorageConfiguration

	connectionFactory authentication.LDAPConnectionFactory
	localProvider     Provider
}

// NewLDAPProvider creates a new instance of LDAPUserProvider.
func NewLDAPProvider(configuration schema.LDAPStorageConfiguration) *LDAPProvider {
	var localProvider Provider
	if configuration.Local != nil {
		localProvider = NewSQLiteProvider(configuration.Local.Path)
	} else if configuration.MySQL != nil {
		localProvider = NewMySQLProvider(*configuration.MySQL)
	} else if configuration.PostgreSQL != nil {
		localProvider = NewPostgreSQLProvider(*configuration.PostgreSQL)
	}
	return &LDAPProvider{
		configuration:     configuration,
		connectionFactory: authentication.NewLDAPConnectionFactoryImpl(),
		localProvider:     localProvider,
	}
}

// NewLDAPProviderWithFactory creates a new instance of LDAPProvider with existing factory.
func NewLDAPProviderWithFactory(configuration schema.LDAPStorageConfiguration,
	connectionFactory authentication.LDAPConnectionFactory) *LDAPProvider {
	return &LDAPProvider{
		configuration:     configuration,
		connectionFactory: connectionFactory,
	}
}

// OWASP recommends to escape some special characters.
// https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.md
const specialLDAPRunes = ",#+<>;\"="

func (l *LDAPProvider) ldapEscape(inputUsername string) string {
	inputUsername = ldap.EscapeFilter(inputUsername)
	for _, c := range specialLDAPRunes {
		inputUsername = strings.ReplaceAll(inputUsername, string(c), fmt.Sprintf("\\%c", c))
	}

	return inputUsername
}

func (l *LDAPProvider) connect(userDN string, password string) (authentication.LDAPConnection, error) {
	var newConnection authentication.LDAPConnection

	url, err := url.Parse(l.configuration.URL)

	if err != nil {
		return nil, fmt.Errorf("Unable to parse URL to LDAP: %s", url)
	}

	if url.Scheme == "ldaps" {
		logging.Logger().Trace("LDAP client starts a TLS session")

		conn, err := l.connectionFactory.DialTLS("tcp", url.Host, &tls.Config{
			InsecureSkipVerify: l.configuration.SkipVerify, //nolint:gosec // This is a configurable option, is desirable in some situations and is off by default
		})
		if err != nil {
			return nil, err
		}

		newConnection = conn
	} else {
		logging.Logger().Trace("LDAP client starts a session over raw TCP")
		conn, err := l.connectionFactory.Dial("tcp", url.Host)
		if err != nil {
			return nil, err
		}
		newConnection = conn
	}

	if err := newConnection.Bind(userDN, password); err != nil {
		return nil, err
	}

	return newConnection, nil
}

func (l *LDAPProvider) resolveUsersFilter(userFilter string, inputUsername string) string {
	inputUsername = l.ldapEscape(inputUsername)

	// We temporarily keep placeholder {0} for backward compatibility.
	userFilter = strings.ReplaceAll(userFilter, "{0}", inputUsername)

	// The {username} placeholder is equivalent to {0}, it's the new way, a named placeholder.
	userFilter = strings.ReplaceAll(userFilter, "{input}", inputUsername)

	// {username_attribute} and {mail_attribute} are replaced by the content of the attribute defined
	// in configuration.
	userFilter = strings.ReplaceAll(userFilter, "{username_attribute}", l.configuration.UsernameAttribute)

	return userFilter
}

func (l *LDAPProvider) verifyUserConnection(conn authentication.LDAPConnection, inputUsername string) (*ldap.SearchResult, error) {
	userFilter := l.resolveUsersFilter(l.configuration.UsersFilter, inputUsername)
	logging.Logger().Tracef("Computed user filter is %s", userFilter)

	baseDN := l.configuration.BaseDN
	if l.configuration.AdditionalUsersDN != "" {
		baseDN = l.configuration.AdditionalUsersDN + "," + baseDN
	}

	attributes := []string{"dn",
		l.configuration.MFAMethodAttribute,
		l.configuration.MFASecretAttribute}

	// Search for the given username.
	searchRequest := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1, 0, false, userFilter, attributes, nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("Cannot find user DN of user %s. Cause: %s", inputUsername, err)
	}

	if len(sr.Entries) == 0 {
		return nil, authentication.ErrUserNotFound
	}

	if len(sr.Entries) > 1 {
		return nil, fmt.Errorf("Multiple users %s found", inputUsername)
	}

	if sr.Entries[0].DN == "" {
		return nil, fmt.Errorf("No DN has been found for user %s", inputUsername)
	}

	return sr, nil
}

func (l *LDAPProvider) getStorageProfile(conn authentication.LDAPConnection, inputUsername string) (*ldapStorageProfile, error) {
	sr, err := l.verifyUserConnection(conn, inputUsername)
	if err != nil {
		return nil, err
	}

	userStorageProfile := ldapStorageProfile{
		DN: sr.Entries[0].DN,
	}

	for _, attr := range sr.Entries[0].Attributes {
		switch attr.Name {
		case l.configuration.MFAMethodAttribute:
			userStorageProfile.Method = attr.Values[0]
		case l.configuration.MFASecretAttribute:
			userStorageProfile.Secret = attr.Values[0]
		}

		if attr.Name == l.configuration.UsernameAttribute {
			if len(attr.Values) != 1 {
				return nil, fmt.Errorf("User %s cannot have multiple value for attribute %s",
					inputUsername, l.configuration.UsernameAttribute)
			}

			userStorageProfile.Username = attr.Values[0]
		}
	}

	return &userStorageProfile, nil
}

func (l *LDAPProvider) putMFASecret(conn authentication.LDAPConnection, inputUsername, secret string) error {
	sr, err := l.verifyUserConnection(conn, inputUsername)
	if err != nil {
		return err
	}

	modifyRequest := ldap.NewModifyRequest(sr.Entries[0].DN, nil)
	modifyRequest.Replace(l.configuration.MFASecretAttribute, []string{secret})

	return conn.Modify(modifyRequest)
}

func (l *LDAPProvider) deleteMFASecret(conn authentication.LDAPConnection, inputUsername string) error {
	sr, err := l.verifyUserConnection(conn, inputUsername)
	if err != nil {
		return err
	}

	modifyRequest := ldap.NewModifyRequest(sr.Entries[0].DN, nil)
	modifyRequest.Delete(l.configuration.MFASecretAttribute, sr.Entries[0].GetAttributeValues(l.configuration.MFASecretAttribute))

	return conn.Modify(modifyRequest)
}

func (l *LDAPProvider) putMFAMethod(conn authentication.LDAPConnection, inputUsername, method string) error {
	sr, err := l.verifyUserConnection(conn, inputUsername)
	if err != nil {
		return err
	}

	modifyRequest := ldap.NewModifyRequest(sr.Entries[0].DN, nil)
	modifyRequest.Replace(l.configuration.MFAMethodAttribute, []string{method})

	return conn.Modify(modifyRequest)
}

func (l *LDAPProvider) deleteMFAMethod(conn authentication.LDAPConnection, inputUsername string) error {
	sr, err := l.verifyUserConnection(conn, inputUsername)
	if err != nil {
		return err
	}

	modifyRequest := ldap.NewModifyRequest(sr.Entries[0].DN, nil)
	modifyRequest.Delete(l.configuration.MFAMethodAttribute, sr.Entries[0].GetAttributeValues(l.configuration.MFAMethodAttribute))

	return conn.Modify(modifyRequest)
}

// LoadPreferred2FAMethod load the preferred method for 2FA from LDAP.
func (l *LDAPProvider) LoadPreferred2FAMethod(username string) (string, error) {
	adminClient, err := l.connect(l.configuration.User, l.configuration.Password)
	if err != nil {
		return "", err
	}
	defer adminClient.Close()

	profile, err := l.getStorageProfile(adminClient, username)
	if err != nil {
		return "", err
	}

	return profile.Method, nil
}

// SavePreferred2FAMethod save the preferred method for 2FA in LDAP.
func (l *LDAPProvider) SavePreferred2FAMethod(username string, method string) error {
	adminClient, err := l.connect(l.configuration.User, l.configuration.Password)
	if err != nil {
		return err
	}
	defer adminClient.Close()

	return l.putMFAMethod(adminClient, username, method)
}

// FindIdentityVerificationToken look for an identity verification token in LDAP.
func (l *LDAPProvider) FindIdentityVerificationToken(token string) (bool, error) {
	if l.localProvider == nil {
		return false, errors.New("missing local storage provider")
	}

	return l.localProvider.FindIdentityVerificationToken(token)
}

// SaveIdentityVerificationToken save an identity verification token in LDAP.
func (l *LDAPProvider) SaveIdentityVerificationToken(token string) error {
	if l.localProvider == nil {
		return errors.New("missing local storage provider")
	}

	return l.localProvider.SaveIdentityVerificationToken(token)
}

// RemoveIdentityVerificationToken remove an identity verification token from the LDAP.
func (l *LDAPProvider) RemoveIdentityVerificationToken(token string) error {
	if l.localProvider == nil {
		return errors.New("missing local storage provider")
	}

	return l.localProvider.RemoveIdentityVerificationToken(token)
}

// SaveTOTPSecret save a TOTP secret of a given user.
func (l *LDAPProvider) SaveTOTPSecret(username string, secret string) error {
	adminClient, err := l.connect(l.configuration.User, l.configuration.Password)
	if err != nil {
		return err
	}
	defer adminClient.Close()

	return l.putMFASecret(adminClient, username, secret)
}

// LoadTOTPSecret load a TOTP secret given a username.
func (l *LDAPProvider) LoadTOTPSecret(username string) (string, error) {
	adminClient, err := l.connect(l.configuration.User, l.configuration.Password)
	if err != nil {
		return "", err
	}
	defer adminClient.Close()

	profile, err := l.getStorageProfile(adminClient, username)
	if err != nil {
		return "", err
	}

	if profile.Secret == "" {
		return profile.Secret, ErrNoTOTPSecret
	}

	return profile.Secret, nil
}

// DeleteTOTPSecret delete a TOTP secret given a username.
func (l *LDAPProvider) DeleteTOTPSecret(username string) error {
	adminClient, err := l.connect(l.configuration.User, l.configuration.Password)
	if err != nil {
		return err
	}
	defer adminClient.Close()

	return l.deleteMFASecret(adminClient, username)
}

// SaveU2FDeviceHandle save a registered U2F device registration blob.
func (l *LDAPProvider) SaveU2FDeviceHandle(username string, keyHandle []byte, publicKey []byte) error {

	dh := ldapU2FDeviceHandle{
		keyHandle: keyHandle,
		publicKey: publicKey,
	}
	secret, err := json.Marshal(dh)
	if err != nil {
		return err
	}

	adminClient, err := l.connect(l.configuration.User, l.configuration.Password)
	if err != nil {
		return err
	}
	defer adminClient.Close()

	return l.putMFASecret(adminClient, username, string(secret))
}

// LoadU2FDeviceHandle load a U2F device registration blob for a given username.
func (l *LDAPProvider) LoadU2FDeviceHandle(username string) (keyHandle []byte, publicKey []byte, err error) {
	dh := ldapU2FDeviceHandle{
		keyHandle: []byte{},
		publicKey: []byte{},
	}

	adminClient, err := l.connect(l.configuration.User, l.configuration.Password)
	if err != nil {
		return nil, nil, err
	}
	defer adminClient.Close()

	profile, err := l.getStorageProfile(adminClient, username)
	if err != nil {
		return nil, nil, err
	}

	err = json.Unmarshal([]byte(profile.Secret), &dh)
	if err != nil {
		return nil, nil, ErrNoU2FDeviceHandle
	}

	return dh.keyHandle, dh.publicKey, nil
}

// AppendAuthenticationLog append a mark to the authentication log.
func (l *LDAPProvider) AppendAuthenticationLog(attempt models.AuthenticationAttempt) error {
	if l.localProvider == nil {
		return errors.New("missing local storage provider")
	}

	return l.localProvider.AppendAuthenticationLog(attempt)
}

// LoadLatestAuthenticationLogs retrieve the latest marks from the authentication log.
func (l *LDAPProvider) LoadLatestAuthenticationLogs(username string, fromDate time.Time) ([]models.AuthenticationAttempt, error) {
	if l.localProvider == nil {
		return nil, errors.New("missing local storage provider")
	}

	return l.localProvider.LoadLatestAuthenticationLogs(username, fromDate)
}
