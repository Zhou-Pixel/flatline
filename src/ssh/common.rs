pub mod code {
    pub const SSH_MSG_DISCONNECT: u8 = 1;
    pub const SSH_MSG_IGNORE: u8 = 2;
    pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
    pub const SSH_MSG_DEBUG: u8 = 4;
    pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
    pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
    pub const SSH_MSG_EXT_INFO: u8 = 7;

    pub const SSH_MSG_KEXINIT: u8 = 20;
    pub const SSH_MSG_NEWKEYS: u8 = 21;

    pub const SSH_MSG_KEXDH_INIT: u8 = 30;
    pub const SSH_MSG_KEXDH_REPLY: u8 = 31;

    pub const SSH_MSG_KEX_DH_GEX_REQUEST_OLD: u8 = 30;
    pub const SSH_MSG_KEX_DH_GEX_REQUEST: u8 = 34;
    pub const SSH_MSG_KEX_DH_GEX_GROUP: u8 = 31;
    pub const SSH_MSG_KEX_DH_GEX_INIT: u8 = 32;
    pub const SSH_MSG_KEX_DH_GEX_REPLY: u8 = 33;

    pub const SSH2_MSG_KEX_ECDH_INIT: u8 = 30;
    pub const SSH2_MSG_KEX_ECDH_REPLY: u8 = 31;

    pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
    pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
    pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
    pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;

    pub const SSH_MSG_USERAUTH_PK_OK: u8 = 60;
    pub const SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: u8 = 60;
    pub const SSH_MSG_USERAUTH_INFO_REQUEST: u8 = 60;
    pub const SSH_MSG_USERAUTH_INFO_RESPONSE: u8 = 61;

    pub const SSH_MSG_GLOBAL_REQUEST: u8 = 80;
    pub const SSH_MSG_REQUEST_SUCCESS: u8 = 81;
    pub const SSH_MSG_REQUEST_FAILURE: u8 = 82;

    pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
    pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
    pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
    pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
    pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
    pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
    pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
    pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
    pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
    pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

    pub const SSH2_MSG_PING: u8 = 192;
    pub const SSH2_MSG_PONG: u8 = 193;

    // pub const SSH_MSG_KEX_DH_GEX_REQUEST_OLD: u8 =  30;
    // pub const SSH_MSG_KEX_DH_GEX_REQUEST: u8 =      34;
    // pub const SSH_MSG_KEX_DH_GEX_GROUP: u8 =        31;
    // pub const SSH_MSG_KEX_DH_GEX_INIT: u8 =         32;
    // pub const SSH_MSG_KEX_DH_GEX_REPLY: u8 =        33;

    pub const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
    pub const SSH_OPEN_CONNECT_FAILED: u32 = 2;
    pub const SSH_OPEN_UNKNOWN_CHANNELTYPE: u32 = 3;
    pub const SSH_OPEN_RESOURCE_SHORTAGE: u32 = 4;

    // pub const SSH_MSG_USERAUTH_REQUEST: u8 =            50;
    // pub const SSH_MSG_USERAUTH_FAILURE: u8 =            51;
    // pub const SSH_MSG_USERAUTH_SUCCESS: u8 =            52;
    // pub const SSH_MSG_USERAUTH_BANNER: u8  =           53;
    pub const SSH_EXTENDED_DATA_STDERR: u32 = 1;

    pub const SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT: u32 = 1;
    pub const SSH_DISCONNECT_PROTOCOL_ERROR: u32 = 2;
    pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED: u32 = 3;
    pub const SSH_DISCONNECT_RESERVED: u32 = 4;
    pub const SSH_DISCONNECT_MAC_ERROR: u32 = 5;
    pub const SSH_DISCONNECT_COMPRESSION_ERROR: u32 = 6;
    pub const SSH_DISCONNECT_SERVICE_NOT_AVAILABLE: u32 = 7;
    pub const SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: u32 = 8;
    pub const SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE: u32 = 9;
    pub const SSH_DISCONNECT_CONNECTION_LOST: u32 = 10;
    pub const SSH_DISCONNECT_BY_APPLICATION: u32 = 11;
    pub const SSH_DISCONNECT_TOO_MANY_CONNECTIONS: u32 = 12;
    pub const SSH_DISCONNECT_AUTH_CANCELLED_BY_USER: u32 = 13;
    pub const SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;
    pub const SSH_DISCONNECT_ILLEGAL_USER_NAME: u32 = 15;

    pub const SSH_FXP_INIT: u8 = 1;
    pub const SSH_FXP_VERSION: u8 = 2;
    pub const SSH_FXP_OPEN: u8 = 3;
    pub const SSH_FXP_CLOSE: u8 = 4;
    pub const SSH_FXP_READ: u8 = 5;
    pub const SSH_FXP_WRITE: u8 = 6;
    pub const SSH_FXP_LSTAT: u8 = 7;
    pub const SSH_FXP_FSTAT: u8 = 8;
    pub const SSH_FXP_SETSTAT: u8 = 9;
    pub const SSH_FXP_FSETSTAT: u8 = 10;
    pub const SSH_FXP_OPENDIR: u8 = 11;
    pub const SSH_FXP_READDIR: u8 = 12;
    pub const SSH_FXP_REMOVE: u8 = 13;
    pub const SSH_FXP_MKDIR: u8 = 14;
    pub const SSH_FXP_RMDIR: u8 = 15;
    pub const SSH_FXP_REALPATH: u8 = 16;
    pub const SSH_FXP_STAT: u8 = 17;
    pub const SSH_FXP_RENAME: u8 = 18;
    pub const SSH_FXP_READLINK: u8 = 19;
    pub const SSH_FXP_SYMLINK: u8 = 20;
    // pub const SSH_FXP_LINK: u8 = 21;
    // pub const SSH_FXP_BLOCK: u8 = 22;
    // pub const SSH_FXP_UNBLOCK: u8 = 23;

    pub const SSH_FXP_STATUS: u8 = 101;
    pub const SSH_FXP_HANDLE: u8 = 102;
    pub const SSH_FXP_DATA: u8 = 103;
    pub const SSH_FXP_NAME: u8 = 104;
    pub const SSH_FXP_ATTRS: u8 = 105;

    // pub const SSH_FXP_EXTENDED: u8 = 200;
    // pub const SSH_FXP_EXTENDED_REPLY: u8 = 201;

    // pub const SSH_FXF_ACCESS_DISPOSITION: u32 = 0x00000007;
    // pub const SSH_FXF_CREATE_NEW: u32 = 0x00000000;
    // pub const SSH_FXF_CREATE_TRUNCATE: u32 = 0x00000001;
    // pub const SSH_FXF_OPEN_EXISTING: u32 = 0x00000002;
    // pub const SSH_FXF_OPEN_OR_CREATE: u32 = 0x00000003;
    // pub const SSH_FXF_TRUNCATE_EXISTING: u32 = 0x00000004;
    // pub const SSH_FXF_APPEND_DATA: u32 = 0x00000008;
    // pub const SSH_FXF_APPEND_DATA_ATOMIC: u32 = 0x00000010;
    // pub const SSH_FXF_TEXT_MODE: u32 = 0x00000020;
    // pub const SSH_FXF_BLOCK_READ: u32 = 0x00000040;
    // pub const SSH_FXF_BLOCK_WRITE: u32 = 0x00000080;
    // pub const SSH_FXF_BLOCK_DELETE: u32 = 0x00000100;
    // pub const SSH_FXF_BLOCK_ADVISORY: u32 = 0x00000200;
    // pub const SSH_FXF_NOFOLLOW: u32 = 0x00000400;
    // pub const SSH_FXF_DELETE_ON_CLOSE: u32 = 0x00000800;
    // pub const SSH_FXF_ACCESS_AUDIT_ALARM_INFO: u32 = 0x00001000;
    // pub const SSH_FXF_ACCESS_BACKUP: u32 = 0x00002000;
    // pub const SSH_FXF_BACKUP_STREAM: u32 = 0x00004000;
    // pub const SSH_FXF_OVERRIDE_OWNER: u32 = 0x00008000;

    pub const SSH_FXF_READ: u32 = 0x00000001;
    pub const SSH_FXF_WRITE: u32 = 0x00000002;
    pub const SSH_FXF_APPEND: u32 = 0x00000004;
    pub const SSH_FXF_CREAT: u32 = 0x00000008;
    pub const SSH_FXF_TRUNC: u32 = 0x00000010;
    pub const SSH_FXF_EXCL: u32 = 0x00000020;

    pub const SSH_FILEXFER_ATTR_SIZE: u32 = 0x00000001;
    pub const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x00000002;
    pub const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x00000004;
    pub const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x00000008;
    pub const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x80000000;

    pub const SSH_FX_OK: u32 = 0;
    pub const SSH_FX_EOF: u32 = 1;
    pub const SSH_FX_NO_SUCH_FILE: u32 = 2;
    pub const SSH_FX_PERMISSION_DENIED: u32 = 3;
    pub const SSH_FX_FAILURE: u32 = 4;
    pub const SSH_FX_BAD_MESSAGE: u32 = 5;
    pub const SSH_FX_NO_CONNECTION: u32 = 6;
    pub const SSH_FX_CONNECTION_LOST: u32 = 7;
    pub const SSH_FX_OP_UNSUPPORTED: u32 = 8;
}

pub const KEX_STRICT_CLIENT: &str = "kex-strict-c-v00@openssh.com";
pub const EXT_INFO_CLIENT: &str = "ext-info-c";

pub const KEX_STRICT_SERVER: &str = "kex-strict-s-v00@openssh.com";
pub const EXT_INFO_SERVER: &str = "ext-info-s";

pub const SFTP_VERSION: u32 = 3;

// https://datatracker.ietf.org/doc/html/rfc4253#section-6.1
pub const PAYLOAD_MAXIMUM_SIZE: usize = 32768;
pub const PACKET_MAXIMUM_SIZE: usize = 35000;
