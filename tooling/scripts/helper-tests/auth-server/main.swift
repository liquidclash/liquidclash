import Foundation
import Darwin

guard CommandLine.arguments.count == 3 else { exit(2) }
let socketPath = CommandLine.arguments[1]
let expectAllowed = CommandLine.arguments[2] == "allow"
guard expectAllowed || CommandLine.arguments[2] == "reject" else { exit(2) }

let fd = socket(AF_UNIX, SOCK_STREAM, 0)
guard fd >= 0 else { exit(3) }
defer {
    close(fd)
    unlink(socketPath)
}

var address = sockaddr_un()
address.sun_family = sa_family_t(AF_UNIX)
let copied = socketPath.withCString { source in
    withUnsafeMutablePointer(to: &address.sun_path) { tuple in
        tuple.withMemoryRebound(to: CChar.self, capacity: 104) {
            strlcpy($0, source, 104)
        }
    }
}
guard copied < 104 else { exit(3) }
let bound = withUnsafePointer(to: &address) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
    }
}
guard bound == 0, chmod(socketPath, 0o600) == 0, listen(fd, 1) == 0 else {
    exit(3)
}

let client = accept(fd, nil, nil)
guard client >= 0 else { exit(3) }
defer { close(client) }

let authorizer = try TonoPeerAuthorizer(allowedUID: getuid())
let allowed = authorizer.accepts(socket: client)
var response: UInt8 = allowed ? 1 : 0
_ = Darwin.write(client, &response, 1)
exit(allowed == expectAllowed ? 0 : 1)
