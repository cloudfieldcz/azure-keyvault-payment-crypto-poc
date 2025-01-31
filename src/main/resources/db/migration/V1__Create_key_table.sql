CREATE TABLE cryptographic_key
(
    id            BIGSERIAL PRIMARY KEY,
    key_alias     VARCHAR(255)                        NOT NULL,
    key_data      TEXT                                NOT NULL,
    key_algorithm VARCHAR(255)                        NOT NULL,
    key_type      VARCHAR(255)                        NOT NULL,
    key_version   VARCHAR(255)                        NOT NULL,
    created       TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated       TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

