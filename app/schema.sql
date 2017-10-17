BEGIN TRANSACTION;
CREATE TABLE "Users" (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`username`	TEXT NOT NULL UNIQUE,
	`password_salt`	TEXT NOT NULL,
	`password_token`	TEXT NOT NULL,
	`is_admin`	INTEGER NOT NULL
);
CREATE TABLE `Sessions` (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`user_id` REFERENCES Users(id) ON DELETE CASCADE,
	`session_token`	TEXT NOT NULL UNIQUE
);
CREATE TABLE `Posts` (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`author_id` REFERENCES Users(id) ON DELETE CASCADE,
	`content`	TEXT,
	`attachment_name`	TEXT,
	`timestamp`	INTEGER
);
CREATE TABLE `Messages` (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`author_id` REFERENCES Users(id) ON DELETE CASCADE,
	`recipient_id` REFERENCES Users(id) ON DELETE CASCADE,
	`content`	TEXT,
	`filename`	TEXT,
	`timestamp`	INTEGER
);
CREATE TABLE `Files` (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`extension`	TEXT NOT NULL
);
CREATE TABLE `FilePermissions` (
	`file_id`	REFERENCES Files(id) ON DELETE CASCADE,
	`user_id`	REFERENCES Users(id) ON DELETE CASCADE,
	PRIMARY KEY(file_id,user_id)
);
COMMIT;
