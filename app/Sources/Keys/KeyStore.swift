// KeyStore.swift — Brev's keychain items, its folder, and the instance lock.
//
// Upholds CLAUDE.md §1.9 (keys ThisDeviceOnly, never synchronizable; the
// folder is excluded from Time Machine) and §3.2 / §3.3 as changed by
// docs/DECISIONS.md D-0035 (docs/PHASE2_DESIGN.md §5.1, §5.2):
// - Keychain: the identity key and the KEK are permanent Secure Enclave
//   SecKeys, and the wrapped DEK is a generic-password item, all three in
//   the data protection keychain under the access group
//   AV26DNQ5SC.no.brev.app. The keychain binds them to Brev's signing
//   identity, so no other program can use, read or replace them, on a Mac
//   that does not hold Brev's team signing key: on one that does, any
//   same-user process can sign itself into that identity (CLAUDE.md §2;
//   docs/DECISIONS.md D-0062). Creating, finding, reading and deleting
//   never prompts: every query that does not unwrap carries an LAContext
//   that forbids interaction, so it fails instead of showing UI. Only
//   UnlockService's unwrap prompts.
// - Install marker: Brev is installed when the wrapped-DEK item exists. It
//   is written last, after the first Touch ID unlock (design §2.10;
//   D-0036), so a crash before that leaves Brev uninstalled, and the next
//   attempt starts with the known-name cleanup.
// - Folder: ~/Library/Containers/no.brev.app/Data/Library/Application
//   Support/Brev, mode 0700, excluded from backups (D-0036). It holds the
//   three stores, `biometry.state` (the enrolled-fingers hash, a hint) and
//   `.lock`, held with O_EXLOCK for the process lifetime so a second Brev
//   cannot run onboarding or open the stores at the same time.
// Nothing secret is ever held here; the wrapped DEK is not secret.
// Not final: the lock probe (app/Tests/Lock) overrides the keychain calls
// to run UnlockService without the keychain.

import Foundation
import LocalAuthentication
import Security

class KeyStore {
    /// The keychain access group of all three items (D-0035). The
    /// entitlement names the same group through $(AppIdentifierPrefix).
    static let accessGroup = "AV26DNQ5SC.no.brev.app"
    static let identityTag = Data("no.brev.app.identity".utf8)
    static let kekTag = Data("no.brev.app.kek".utf8)
    static let wrappedService = "no.brev.app"
    static let wrappedAccount = "wrapped-dek"

    /// Every file Brev writes in `dir`, except `.lock`: the only names the
    /// cleanup ever deletes (design §5.2's rule; its list, which still names
    /// the key files, is replaced by D-0035).
    static let knownFiles = ["brev.db", "brev.db-journal", "peer-1.db", "peer-1.db-journal",
                             "peer-2.db", "peer-2.db-journal", "biometry.state", "biometry.state.tmp"]

    let dir: URL

    init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        dir = support.appendingPathComponent("Brev", isDirectory: true)
    }

    // MARK: - The folder

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

    // MARK: - Install state

    enum Install {
        case installed
        case fresh
        /// The keychain could not be asked (the status says why).
        case unavailable(OSStatus)
    }

    /// Installed means the wrapped-DEK item exists.
    func installState() -> Install {
        var query = wrappedQuery()
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnAttributes as String] = true
        switch SecItemCopyMatching(query as CFDictionary, nil) {
        case errSecSuccess: return .installed
        case errSecItemNotFound: return .fresh
        case let status: return .unavailable(status)
        }
    }

    // MARK: - Keys

    /// Onboarding (design §5.3 step 4): creates the identity key and the
    /// KEK in the Secure Enclave, stored in the keychain. No prompt. Returns
    /// their public keys; the private keys stay in the keychain.
    func makeKeys() throws -> (identityPublic: SecKey, kekPublic: SecKey) {
        let identity = try makeKey(tag: Self.identityTag)
        let kek = try makeKey(tag: Self.kekTag)
        guard let identityPublic = SecKeyCopyPublicKey(identity), let kekPublic = SecKeyCopyPublicKey(kek)
        else { throw Enclave.Failure.unknown }
        return (identityPublic, kekPublic)
    }

    private func makeKey(tag: Data) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: Self.accessGroup,
            kSecUseAuthenticationContext as String: Self.noInteraction(),
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: try Enclave.accessControl(),
            ] as [String: Any],
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &err)
        else { throw err.map { $0.takeRetainedValue() as Error } ?? Enclave.Failure.unknown }
        return key
    }

    /// The KEK, looked up with `context`: the LAContext its unwrap will
    /// prompt with (UnlockService). Finding it does not prompt.
    func kek(context: LAContext) throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: Self.kekTag,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: Self.accessGroup,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        guard status == errSecSuccess, let ref = out, CFGetTypeID(ref) == SecKeyGetTypeID()
        else { throw Self.error(status == errSecSuccess ? errSecItemNotFound : status) }
        return ref as! SecKey   // the type id was checked above
    }

    // MARK: - The wrapped DEK

    /// Install (design §5.3 step 8): adds the wrapped-DEK item. Only after
    /// the first Touch ID unlock of the new stores succeeded.
    func storeWrapped(_ wrapped: Data) throws {
        guard wrapped.count == Enclave.wrappedLength else { throw Enclave.Failure.malformed }
        var item = wrappedQuery()
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        item[kSecAttrSynchronizable as String] = false
        item[kSecValueData as String] = wrapped
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw Self.error(status) }
    }

    /// The wrapped DEK. Throws errSecItemNotFound if it is gone, and
    /// Enclave.Failure.malformed if it has the wrong length.
    func readWrapped() throws -> Data {
        var query = wrappedQuery()
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecReturnData as String] = true
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        guard status == errSecSuccess else { throw Self.error(status) }
        guard let data = out as? Data, data.count == Enclave.wrappedLength else { throw Enclave.Failure.malformed }
        return data
    }

    private func wrappedQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.wrappedService,
            kSecAttrAccount as String: Self.wrappedAccount,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: Self.accessGroup,
            kSecUseAuthenticationContext as String: Self.noInteraction(),
        ]
    }

    // MARK: - Cleanup and reset

    /// Deletes every known name (design §5.2): the wrapped-DEK item first, so
    /// Brev counts as uninstalled from here on, then both keys, then the
    /// known files. Nothing else is ever deleted, and `.lock` stays. Runs
    /// before every onboarding attempt and for a confirmed reset. With backup
    /// exclusion on, only a local APFS snapshot can still hold the old stores;
    /// the keys existed only in this Mac's Secure Enclave and are gone.
    func deleteKnownNames() throws {
        try deleteItems([kSecClass as String: kSecClassGenericPassword,
                         kSecAttrService as String: Self.wrappedService,
                         kSecAttrAccount as String: Self.wrappedAccount])
        for tag in [Self.kekTag, Self.identityTag] {
            try deleteItems([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag])
        }
        for name in Self.knownFiles {
            if unlink(dir.appendingPathComponent(name).path) != 0 && errno != ENOENT {
                throw Self.posixError(errno)
            }
        }
    }

    private func deleteItems(_ match: [String: Any]) throws {
        var query = match
        query[kSecUseDataProtectionKeychain as String] = true
        query[kSecAttrAccessGroup as String] = Self.accessGroup
        query[kSecUseAuthenticationContext as String] = Self.noInteraction()
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw Self.error(status) }
    }

    // MARK: - biometry.state

    /// The enrolled-fingers hash saved at the last successful unlock (or at
    /// onboarding), or nil.
    func readBiometryState() -> Data? {
        guard let data = try? Data(contentsOf: dir.appendingPathComponent("biometry.state")),
              !data.isEmpty, data.count <= 64 else { return nil }
        return data
    }

    /// Replaces `biometry.state` atomically: a new 0600 file written and
    /// synced to the disk, renamed over the old one, then the folder synced.
    func writeBiometryState(_ hash: Data) throws {
        let tmp = dir.appendingPathComponent("biometry.state.tmp").path
        let final = dir.appendingPathComponent("biometry.state").path
        if unlink(tmp) != 0 && errno != ENOENT { throw Self.posixError(errno) }
        let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw Self.posixError(errno) }
        let written = hash.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        let synced = fcntl(fd, F_FULLFSYNC) == 0
        close(fd)
        guard written == hash.count, synced, rename(tmp, final) == 0 else {
            let code = errno
            unlink(tmp)
            throw Self.posixError(code)
        }
        let dirFD = open(dir.path, O_RDONLY | O_CLOEXEC)
        if dirFD >= 0 {
            fsync(dirFD)
            close(dirFD)
        }
    }

    // MARK: - Helpers

    /// A context that turns any authentication UI into an error instead.
    private static func noInteraction() -> LAContext {
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        return ctx
    }

    static func error(_ status: OSStatus) -> NSError {
        NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }

    private static func posixError(_ code: Int32) -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(code))
    }
}
