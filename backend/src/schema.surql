DEFINE TABLE OVERWRITE user SCHEMAFULL;
DEFINE FIELD OVERWRITE username             ON user TYPE string;
DEFINE FIELD OVERWRITE password_hash        ON user TYPE string;
DEFINE FIELD OVERWRITE role                 ON user TYPE string
  ASSERT $value IN ['administrator', 'kierownik', 'redaktor', 'czytelnik'];
DEFINE FIELD OVERWRITE blocked              ON user TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE must_change_password ON user TYPE bool DEFAULT true;
DEFINE FIELD OVERWRITE one_time_expires_at  ON user TYPE option<datetime>;
DEFINE FIELD OVERWRITE password_changed_at  ON user TYPE option<datetime>;
DEFINE FIELD OVERWRITE password_history     ON user TYPE array<string> DEFAULT [];
DEFINE FIELD OVERWRITE otp_expired          ON user VALUE <future> {
    must_change_password AND one_time_expires_at != NONE AND one_time_expires_at < time::now()
};
DEFINE FIELD OVERWRITE password_expired     ON user VALUE <future> {
    password_changed_at != NONE
        AND password_changed_at + duration::from::days(settings:main.password_valid_days) < time::now()
};
DEFINE FIELD OVERWRITE created_at           ON user TYPE datetime DEFAULT time::now();
DEFINE INDEX OVERWRITE user_username        ON user FIELDS username UNIQUE;
REMOVE FIELD IF EXISTS password_expires_at ON user;

-- tylko skrót tokenu, sam token jest w ciasteczku
DEFINE TABLE OVERWRITE session SCHEMAFULL;
DEFINE FIELD OVERWRITE user       ON session TYPE record<user>;
DEFINE FIELD OVERWRITE token_hash ON session TYPE string;
DEFINE FIELD OVERWRITE last_seen  ON session TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE created_at ON session TYPE datetime DEFAULT time::now();
DEFINE INDEX OVERWRITE session_token ON session FIELDS token_hash UNIQUE;

DEFINE TABLE OVERWRITE settings SCHEMAFULL;
DEFINE FIELD OVERWRITE min_length              ON settings TYPE int  DEFAULT 12;
DEFINE FIELD OVERWRITE passphrase_rule_enabled ON settings TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE password_valid_days     ON settings TYPE int  DEFAULT 90;
DEFINE FIELD OVERWRITE idle_timeout_minutes    ON settings TYPE int  DEFAULT 15;
DEFINE FIELD OVERWRITE one_time_valid_hours    ON settings TYPE int  DEFAULT 48;

DEFINE TABLE OVERWRITE note SCHEMAFULL;
DEFINE FIELD OVERWRITE text        ON note TYPE string;
DEFINE FIELD OVERWRITE author      ON note TYPE option<string>;  -- login, nie rekord - notatka zostaje po usunięciu konta
DEFINE FIELD OVERWRITE approved    ON note TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE approved_by ON note TYPE option<string>;
DEFINE FIELD OVERWRITE created_at  ON note TYPE datetime DEFAULT time::now();
UPDATE note SET approved = false WHERE approved = NONE;
