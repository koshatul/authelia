package validator

import (
	"errors"
	"strings"

	"github.com/authelia/authelia/internal/configuration/schema"
)

// ValidateStorage validates storage configuration.
func ValidateStorage(configuration schema.StorageConfiguration, validator *schema.StructValidator) {
	if configuration.Local == nil && configuration.MySQL == nil && configuration.PostgreSQL == nil && configuration.LDAP == nil {
		validator.Push(errors.New("A storage configuration must be provided. It could be 'local', 'mysql', 'postgres' or 'ldap'"))
	}

	switch {
	case configuration.MySQL != nil:
		validateSQLConfiguration(&configuration.MySQL.SQLStorageConfiguration, validator)
	case configuration.PostgreSQL != nil:
		validatePostgreSQLConfiguration(configuration.PostgreSQL, validator)
	case configuration.Local != nil:
		validateLocalStorageConfiguration(configuration.Local, validator)
	case configuration.LDAP != nil:
		validateLDAPStorageConfiguration(configuration.LDAP, validator)
	}
}

func validateSQLConfiguration(configuration *schema.SQLStorageConfiguration, validator *schema.StructValidator) {
	if configuration.Password == "" || configuration.Username == "" {
		validator.Push(errors.New("Username and password must be provided"))
	}

	if configuration.Database == "" {
		validator.Push(errors.New("A database must be provided"))
	}
}

func validatePostgreSQLConfiguration(configuration *schema.PostgreSQLStorageConfiguration, validator *schema.StructValidator) {
	validateSQLConfiguration(&configuration.SQLStorageConfiguration, validator)

	if configuration.SSLMode == "" {
		configuration.SSLMode = testModeDisabled
	}

	if !(configuration.SSLMode == testModeDisabled || configuration.SSLMode == "require" ||
		configuration.SSLMode == "verify-ca" || configuration.SSLMode == "verify-full") {
		validator.Push(errors.New("SSL mode must be 'disable', 'require', 'verify-ca', or 'verify-full'"))
	}
}

func validateLocalStorageConfiguration(configuration *schema.LocalStorageConfiguration, validator *schema.StructValidator) {
	if configuration.Path == "" {
		validator.Push(errors.New("A file path must be provided with key 'path'"))
	}
}

//nolint:gocyclo // TODO: Consider refactoring/simplifying, time permitting
func validateLDAPStorageConfiguration(configuration *schema.LDAPStorageConfiguration, validator *schema.StructValidator) {
	if configuration.URL == "" {
		validator.Push(errors.New("Please provide a URL to the LDAP server"))
	} else {
		configuration.URL = validateLdapURL(configuration.URL, validator)
	}

	// TODO: see if it's possible to disable this check if disable_reset_password is set and when anonymous/user binding is supported (#101 and #387)
	if configuration.User == "" {
		validator.Push(errors.New("Please provide a user name to connect to the LDAP server"))
	}

	// TODO: see if it's possible to disable this check if disable_reset_password is set and when anonymous/user binding is supported (#101 and #387)
	if configuration.Password == "" {
		validator.Push(errors.New("Please provide a password to connect to the LDAP server"))
	}

	if configuration.BaseDN == "" {
		validator.Push(errors.New("Please provide a base DN to connect to the LDAP server"))
	}

	if configuration.UsersFilter == "" {
		validator.Push(errors.New("Please provide a users filter with `users_filter` attribute"))
	} else {
		if !strings.HasPrefix(configuration.UsersFilter, "(") || !strings.HasSuffix(configuration.UsersFilter, ")") {
			validator.Push(errors.New("The users filter should contain enclosing parenthesis. For instance uid={input} should be (uid={input})"))
		}

		// This test helps the user know that users_filter is broken after the breaking change induced by this commit.
		if !strings.Contains(configuration.UsersFilter, "{0}") && !strings.Contains(configuration.UsersFilter, "{input}") {
			validator.Push(errors.New("Unable to detect {input} placeholder in users_filter, your configuration might be broken. " +
				"Please review configuration options listed at https://docs.authelia.com/configuration/authentication/ldap.html"))
		}
	}

	if configuration.UsernameAttribute == "" {
		validator.Push(errors.New("Please provide a username attribute with `username_attribute`"))
	}

	if configuration.MFAMethodAttribute == "" {
		configuration.MFAMethodAttribute = schema.DefaultLDAPStorageBackendConfiguration.MFAMethodAttribute
	}

	if configuration.MFASecretAttribute == "" {
		configuration.MFASecretAttribute = schema.DefaultLDAPStorageBackendConfiguration.MFASecretAttribute
	}
}
