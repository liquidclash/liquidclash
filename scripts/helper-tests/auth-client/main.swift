import Foundation
import Darwin

guard CommandLine.arguments.count == 2 else { exit(2) }
let socketPath = CommandLine.arguments[1]
let fd = socket(AF_UNIX, SOCK_STREAM, 0)
guard fd >= 0 else { exit(3) }
defer { close(fd) }

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
let connected = withUnsafePointer(to: &address) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
    }
}
guard connected == 0 else { exit(3) }
var byte: UInt8 = 0x54
guard Darwin.write(fd, &byte, 1) == 1 else { exit(3) }
guard Darwin.read(fd, &byte, 1) == 1 else { exit(3) }
