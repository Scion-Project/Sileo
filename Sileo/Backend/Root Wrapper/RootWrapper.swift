import Foundation
import Darwin

#if targetEnvironment(macCatalyst)
final public class MacRootWrapper {

    static let shared = MacRootWrapper()
    let sharedPipe = AptRootPipeWrapper()

    public var connection: NSXPCConnection?
    private var invalidated = false
    public var helper: RootHelperProtocol?
    public var wrapperClass: LaunchAsRoot.Type

    init() {
        guard let bundleURL = Bundle.main.builtInPlugInsURL?.appendingPathComponent("SileoRootWrapper.bundle"),
              let bundle = Bundle(url: bundleURL),
              bundle.load(),
              let klass = objc_getClass("LaunchAsRoot") as? LaunchAsRoot.Type
        else {
            fatalError("Unable to initialize ability to spawn a process as root")
        }

        self.wrapperClass = klass
        _ = klass.shared
        func connect() {
            if !connectToDaemon() {
                klass.shared.installDaemon()
                guard connectToDaemon() else {
                    fatalError("[Sileo] Authorization Alpha-Alpha 3-0-5.")
                }
            }
        }
        connect()

        guard let helper = helper else { fatalError("[Sileo] Protocol 3: Protect the Pilot") }
        helper.version { version in
            guard version == DaemonVersion else {
                self.connection?.invalidationHandler = nil
                self.connection?.invalidate()

                klass.shared.installDaemon()
                guard self.connectToDaemon() else {
                    fatalError("[Sileo] Authorization Alpha-Alpha 3-0-5.")
                }
                return
            }
        }
    }

    public func spawn(args: [String], outputCallback: ((_ output: String?) -> Void)? = nil) -> (Int, String, String) {
        guard !args.isEmpty,
              let launchPath = args.first
        else {
            fatalError("Found invalid args when spawning a process as root")
        }

        var arguments = args
        arguments.removeFirst()

        var status = -1
        var stdoutStr = ""
        var stderrStr = ""

        guard let helper = helper else {
            fatalError("[Sileo] Protocol 3: Protect the Pilot")
        }
        // swiftlint:disable identifier_name
        helper.spawn(command: launchPath, args: args) { _status, _stdoutStr, _stderrStr in
            status = _status
            stdoutStr = _stdoutStr
            stderrStr = _stderrStr
        }
        return (status, stdoutStr, stderrStr)
    }

    public func connectToDaemon() -> Bool {
        guard self.connection == nil,
              let connection = wrapperClass.shared.connection(),
              self.helper == nil else { return true }
        connection.remoteObjectInterface = NSXPCInterface(with: RootHelperProtocol.self)
        connection.exportedInterface = NSXPCInterface(with: AptRootPipeProtocol.self)
        connection.exportedObject = sharedPipe
        connection.invalidationHandler = {
            self.invalidated = true
        }

        connection.resume()

        guard let helper = connection.synchronousRemoteObjectProxyWithErrorHandler({ _ in
            return
        }) as? RootHelperProtocol else {
            return false
        }
        var version = ""
        helper.version { _version in
            version = _version
        }
        guard version == DaemonVersion else {
            return false
        }
        self.connection = connection
        self.helper = helper
        return true
    }
    
    public func resetConnection() {
        self.connection?.invalidate()
        self.connection = nil
        self.helper = nil
        
        guard connectToDaemon() else {
            fatalError("[Sileo] Authorization Alpha-Alpha 3-0-5.")
        }
    }
}
#endif

#if !targetEnvironment(macCatalyst) && !targetEnvironment(simulator) && !TARGET_SANDBOX
/// Starting a program as root, on iOS 13 and later.
///
/// Sileo asks the kernel to spawn the program into persona 99 with uid and gid 0. A kernel that refuses (one with no
/// persona 99 and no stand-in for it, as on ports of iOS to other hardware) fails that posix_spawn before the program
/// runs, and the install then stopped without a word: the queue stayed at "Queued" for ever. In that case the program
/// is started through giveMeRoot, the set-user-ID helper in the app bundle (the way Sileo becomes root on iOS 12 and
/// earlier), which checks that its parent is Sileo, becomes root and executes the program. The first refusal is
/// remembered, so later spawns go to giveMeRoot directly.
enum RootSpawn {
    private static let lock = NSLock()
    private static var personaRefused = false

    /// Like posix_spawn(), with `args` as Sileo builds them (args[0] the program's name). Returns 0 or an errno.
    static func spawn(_ pid: UnsafeMutablePointer<pid_t>,
                      command: String,
                      fileActions: UnsafePointer<posix_spawn_file_actions_t?>?,
                      args: [String],
                      env: [String]) -> Int32 {
        let envp: [UnsafeMutablePointer<CChar>?] = env.map { $0.withCString(strdup) }
        defer { for case let pointer? in envp { free(pointer) } }

        lock.lock()
        let tryPersona = !personaRefused
        lock.unlock()

        var status: Int32 = ENOENT
        if tryPersona {
            let argv: [UnsafeMutablePointer<CChar>?] = args.map { $0.withCString(strdup) }
            defer { for case let pointer? in argv { free(pointer) } }
            var attr: posix_spawnattr_t?
            posix_spawnattr_init(&attr)
            defer { posix_spawnattr_destroy(&attr) }
            posix_spawnattr_set_persona_np(&attr, 99, UInt32(POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE))
            posix_spawnattr_set_persona_uid_np(&attr, 0)
            posix_spawnattr_set_persona_gid_np(&attr, 0)
            status = posix_spawn(pid, command, fileActions, &attr, argv + [nil], envp + [nil])
            if status == 0 {
                return 0
            }
            lock.lock()
            personaRefused = true
            lock.unlock()
            NSLog("[Sileo] spawn into persona 99 refused (%d: %@); using giveMeRoot from now on",
                  status, String(cString: strerror(status)))
        }

        guard let giveMeRootPath = Bundle.main.path(forAuxiliaryExecutable: "giveMeRoot") else {
            return status
        }
        // giveMeRoot executes its first argument, with the rest as that program's argv
        let helperArgs = ["giveMeRoot", command] + args.dropFirst()
        let argv: [UnsafeMutablePointer<CChar>?] = helperArgs.map { $0.withCString(strdup) }
        defer { for case let pointer? in argv { free(pointer) } }
        return posix_spawn(pid, giveMeRootPath, fileActions, nil, argv + [nil], envp + [nil])
    }
}
#endif

@discardableResult func spawn(command: String, args: [String], root: Bool = false) -> (Int, String, String) {
    var pipestdout: [Int32] = [0, 0]
    var pipestderr: [Int32] = [0, 0]

    let bufsiz = Int(BUFSIZ)

    pipe(&pipestdout)
    pipe(&pipestderr)

    guard fcntl(pipestdout[0], F_SETFL, O_NONBLOCK) != -1 else {
        return (-1, "", "")
    }
    guard fcntl(pipestderr[0], F_SETFL, O_NONBLOCK) != -1 else {
        return (-1, "", "")
    }

    var fileActions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&fileActions)
    posix_spawn_file_actions_addclose(&fileActions, pipestdout[0])
    posix_spawn_file_actions_addclose(&fileActions, pipestderr[0])
    posix_spawn_file_actions_adddup2(&fileActions, pipestdout[1], STDOUT_FILENO)
    posix_spawn_file_actions_adddup2(&fileActions, pipestderr[1], STDERR_FILENO)
    posix_spawn_file_actions_addclose(&fileActions, pipestdout[1])
    posix_spawn_file_actions_addclose(&fileActions, pipestderr[1])

    let argv: [UnsafeMutablePointer<CChar>?] = args.map { $0.withCString(strdup) }
    defer { for case let arg? in argv { free(arg) } }

    var pid: pid_t = 0

    #if targetEnvironment(macCatalyst)
    let env = [ "PATH=/opt/procursus/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin" ]
    let proenv: [UnsafeMutablePointer<CChar>?] = env.map { $0.withCString(strdup) }
    defer { for case let pro? in proenv { free(pro) } }
    let spawnStatus = posix_spawn(&pid, command, &fileActions, nil, argv + [nil], proenv + [nil])
    #else
    // Weird problem with a weird workaround
    let env = [ "PATH=\(CommandPath.prefix)/usr/bin:\(CommandPath.prefix)/usr/local/bin:\(CommandPath.prefix)/bin:\(CommandPath.prefix)/usr/sbin" ]
    let envp: [UnsafeMutablePointer<CChar>?] = env.map { $0.withCString(strdup) }
    defer { for case let env? in envp { free(env) } }
    
    let spawnStatus: Int32
    if #available(iOS 13, *) {
        if root {
            spawnStatus = RootSpawn.spawn(&pid, command: command, fileActions: &fileActions, args: args, env: env)
        } else {
            spawnStatus = posix_spawn(&pid, command, &fileActions, nil, argv + [nil], envp + [nil])
        }
    } else {
        spawnStatus = posix_spawn(&pid, command, &fileActions, nil, argv + [nil], envp + [nil])
    }
    #endif
    if spawnStatus != 0 {
        for fd in pipestdout + pipestderr { close(fd) }
        return (Int(spawnStatus), "ITS FAILING HERE", "Error = \(errno)  \(String(cString: strerror(spawnStatus))) \(String(cString: strerror(errno)))\n\(command)")
    }

    close(pipestdout[1])
    close(pipestderr[1])

    var stdoutStr = ""
    var stderrStr = ""

    let mutex = DispatchSemaphore(value: 0)

    let readQueue = DispatchQueue(label: "org.coolstar.sileo.command",
                                  qos: .userInitiated,
                                  attributes: .concurrent,
                                  autoreleaseFrequency: .inherit,
                                  target: nil)

    let stdoutSource = DispatchSource.makeReadSource(fileDescriptor: pipestdout[0], queue: readQueue)
    let stderrSource = DispatchSource.makeReadSource(fileDescriptor: pipestderr[0], queue: readQueue)

    stdoutSource.setCancelHandler {
        close(pipestdout[0])
        mutex.signal()
    }
    stderrSource.setCancelHandler {
        close(pipestderr[0])
        mutex.signal()
    }

    stdoutSource.setEventHandler {
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufsiz)
        defer { buffer.deallocate() }

        let bytesRead = read(pipestdout[0], buffer, bufsiz)
        guard bytesRead > 0 else {
            if bytesRead == -1 && errno == EAGAIN {
                return
            }

            stdoutSource.cancel()
            return
        }

        let array = Array(UnsafeBufferPointer(start: buffer, count: bytesRead)) + [UInt8(0)]
        array.withUnsafeBufferPointer { ptr in
            let str = String(cString: unsafeBitCast(ptr.baseAddress, to: UnsafePointer<CChar>.self))
            stdoutStr += str
        }
    }
    stderrSource.setEventHandler {
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufsiz)
        defer { buffer.deallocate() }

        let bytesRead = read(pipestderr[0], buffer, bufsiz)
        guard bytesRead > 0 else {
            if bytesRead == -1 && errno == EAGAIN {
                return
            }

            stderrSource.cancel()
            return
        }

        let array = Array(UnsafeBufferPointer(start: buffer, count: bytesRead)) + [UInt8(0)]
        array.withUnsafeBufferPointer { ptr in
            let str = String(cString: unsafeBitCast(ptr.baseAddress, to: UnsafePointer<CChar>.self))
            stderrStr += str
        }
    }

    stdoutSource.resume()
    stderrSource.resume()

    mutex.wait()
    mutex.wait()
    var status: Int32 = 0
    waitpid(pid, &status, 0)

    return (Int(status), stdoutStr, stderrStr)
}

@discardableResult func spawnAsRoot(args: [String], platformatise: Bool = false, outputCallback: ((_ output: String?) -> Void)? = nil) -> (Int, String, String) {
    #if targetEnvironment(simulator) || TARGET_SANDBOX
    fatalError("Commands should not be run in sandbox")
    #elseif targetEnvironment(macCatalyst)
    MacRootWrapper.shared.spawn(args: args, outputCallback: outputCallback)
    #else
    if #available(iOS 13, *) {
        var args = args
        let command = args.first!
        args[0] = String(command.split(separator: "/").last!)
        return spawn(command:command, args: args, root: true)
    } else {
        guard let giveMeRootPath = Bundle.main.path(forAuxiliaryExecutable: "giveMeRoot") else {
            return (-1, "", "")
        }
        return spawn(command: giveMeRootPath, args: ["giveMeRoot"] + args)
    }
    #endif
}

func deleteFileAsRoot(_ url: URL) {
    #if targetEnvironment(simulator) || TARGET_SANDBOX
    try? FileManager.default.removeItem(at: url)
    #else
    spawnAsRoot(args: [CommandPath.rm, "-rf", "\(url.path)"])
    #endif
}

func hardLinkAsRoot(from: URL, to: URL) {
    deleteFileAsRoot(to)

    #if targetEnvironment(simulator) || TARGET_SANDBOX
    try? FileManager.default.createSymbolicLink(at: to, withDestinationURL: from)
    #else
    spawnAsRoot(args: [CommandPath.ln, "\(from.path)", "\(to.path)"])
    spawnAsRoot(args: [CommandPath.chown, "0:0", "\(to.path)"])
    spawnAsRoot(args: [CommandPath.chmod, "0644", "\(to.path)"])
    #endif
}

func moveFileAsRoot(from: URL, to: URL) {
    deleteFileAsRoot(to)

    #if targetEnvironment(simulator) || TARGET_SANDBOX
    try? FileManager.default.moveItem(at: from, to: to)
    #else
    spawnAsRoot(args: [CommandPath.mv, "\(from.path)", "\(to.path)"])
    spawnAsRoot(args: [CommandPath.chown, "0:0", "\(to.path)"])
    spawnAsRoot(args: [CommandPath.chmod, "0644", "\(to.path)"])
    #endif
}

