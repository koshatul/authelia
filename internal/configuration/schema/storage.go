package schema

// LDAPStorageConfiguration represents the configuration related to LDAP server for MFA storage.
type LDAPStorageConfiguration struct {
	URL                string                          `mapstructure:"url"`
	SkipVerify         bool                            `mapstructure:"skip_verify"`
	BaseDN             string                          `mapstructure:"base_dn"`
	AdditionalUsersDN  string                          `mapstructure:"additional_users_dn"`
	UsersFilter        string                          `mapstructure:"users_filter"`
	UsernameAttribute  string                          `mapstructure:"username_attribute"`
	MFAMethodAttribute string                          `mapstructure:"mfamethod_attribute"`
	MFASecretAttribute string                          `mapstructure:"mfasecret_attribute"`
	User               string                          `mapstructure:"user"`
	Password           string                          `mapstructure:"password"`
	Local              *LocalStorageConfiguration      `mapstructure:"local"`
	MySQL              *MySQLStorageConfiguration      `mapstructure:"mysql"`
	PostgreSQL         *PostgreSQLStorageConfiguration `mapstructure:"postgres"`
}

// LocalStorageConfiguration represents the configuration when using local storage.
type LocalStorageConfiguration struct {
	Path string `mapstructure:"path"`
}

// SQLStorageConfiguration represents the configuration of the SQL database.
type SQLStorageConfiguration struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Database string `mapstructure:"database"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// MySQLStorageConfiguration represents the configuration of a MySQL database.
type MySQLStorageConfiguration struct {
	SQLStorageConfiguration `mapstructure:",squash"`
}

// PostgreSQLStorageConfiguration represents the configuration of a Postgres database.
type PostgreSQLStorageConfiguration struct {
	SQLStorageConfiguration `mapstructure:",squash"`
	SSLMode                 string `mapstructure:"sslmode"`
}

// StorageConfiguration represents the configuration of the storage backend.
type StorageConfiguration struct {
	Local      *LocalStorageConfiguration      `mapstructure:"local"`
	MySQL      *MySQLStorageConfiguration      `mapstructure:"mysql"`
	PostgreSQL *PostgreSQLStorageConfiguration `mapstructure:"postgres"`
	LDAP       *LDAPStorageConfiguration       `mapstructure:"ldap"`
}

// DefaultLDAPStorageBackendConfiguration represents the default LDAP config.
var DefaultLDAPStorageBackendConfiguration = LDAPStorageConfiguration{
	MFAMethodAttribute: "mfaMethod",
	MFASecretAttribute: "mfaSecret",
}
