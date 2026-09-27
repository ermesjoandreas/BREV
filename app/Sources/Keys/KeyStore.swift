// KeyStore.swift — Brev's folder in its container, and the instance lock.
//
// Upholds CLAUDE.md §1.9 (the folder is excluded from Time Machine) and §3.2
// (docs/PHASE2_DESIGN.md §5.1, §5.2). The folder is
// ~/Library/Containers/no.brev.app/Data/Library/Application Support/Brev,
// mode 0700. `.lock` in it is held with O_EXLOCK for the process lifetime,
// so a second Brev process cannot run onboarding or open the stores at the
// same time. Paths and file handling only: no secret is ever held here.

import Foundation

final class KeyStore {
    let dir: URL

    init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        dir = support.appendingPathComponent("Brev", isDirectory: true)
    }

    /// Onboarding finished: `dek.hpke` is written last (§2.10), so nothing
    /// counts as installed before it exists.
    var isInstalled: Bool {
        FileManager.default.fileExists(atPath: dir.appendingPathComponent("dek.hpke").path)
    }

    /// Creates the folder with mode 0700 if needed, keeps it at 0700, and
    /// excludes it from backups.
    func prepareDirectory() throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        if try dir.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup != true {
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var url = dir
            try url.setResourceValues(values)
        }
    }

    enum InstanceLock {
        /// The descriptor holds the lock; it is never closed.
        case held(Int32)
        /// Another Brev process holds it.
        case busy
        case failed(errno: Int32)
    }

    /// Takes `.lock` without waiting.
    func takeInstanceLock() -> InstanceLock {
        let fd = open(dir.appendingPathComponent(".lock").path,
                      O_CREAT | O_RDWR | O_EXLOCK | O_NONBLOCK | O_CLOEXEC, 0o600)
        if fd >= 0 { return .held(fd) }
        let code = errno
        return code == EWOULDBLOCK ? .busy : .failed(errno: code)
    }
}
