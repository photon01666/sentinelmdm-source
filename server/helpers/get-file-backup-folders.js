// helpers/get-file-backup-folders.js — get file backup folders for a device.
//
// A HELPER module, not a route module: it registers nothing.
//
//   getFileBackupFolders   export   get file backup folders with defaults
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 2 deps: FILE_BACKUP_KNOWN_FOLDERS (binding L3960), db (binding L646).  The call must sit at or after L3961; the earliest consumer of
// the export is L3976, so at or before L3975.  L3962 satisfies both.
//
// relative requires: none

module.exports = ({ FILE_BACKUP_KNOWN_FOLDERS, db }) => {
async function getFileBackupFolders(deviceId) {
  const defaults = { wellKnown: [...FILE_BACKUP_KNOWN_FOLDERS], customPaths: [] };
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('file_backup_folders:' + deviceId));
  if (!row) return defaults;
  try {
    const parsed = JSON.parse(row.value);
    return {
      wellKnown: Array.isArray(parsed.wellKnown)
        ? parsed.wellKnown.filter(f => FILE_BACKUP_KNOWN_FOLDERS.includes(f)) : defaults.wellKnown,
      customPaths: Array.isArray(parsed.customPaths) ? parsed.customPaths : defaults.customPaths,
    };
  } catch { return defaults; }
}

  return {
    getFileBackupFolders,
  };
};