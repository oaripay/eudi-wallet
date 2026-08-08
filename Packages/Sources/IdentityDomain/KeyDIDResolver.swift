import CryptoKit
import Foundation

public struct KeyDIDResolver: DIDResolver, Sendable {
    private static let p256Multicodec = 0x1200
    private static let jwkJCSMultiCodec = 0xeb51

    public init() {}

    public func resolve(_ did: String) async throws -> DIDDocument {
        guard did.utf8.count <= 256 else { throw DIDResolutionError.invalidDID }
        guard did.hasPrefix("did:key:z") else { throw DIDResolutionError.unsupportedMethod }
        let identifier = String(did.dropFirst("did:key:".count))
        let decoded = try Base58BTC.decode(identifier)
        let (code, offset) = try Varint.decode(decoded)
        guard Array(decoded.prefix(offset)) == Varint.encode(code) else {
            throw DIDResolutionError.malformedKey
        }
        let jwk: PublicJWK
        switch code {
        case Self.p256Multicodec:
            let compressed = Data(decoded.dropFirst(offset))
            guard compressed.count == 33 else { throw DIDResolutionError.malformedKey }
            let publicKey: P256.Signing.PublicKey
            do {
                publicKey = try P256.Signing.PublicKey(compressedRepresentation: compressed)
            } catch {
                throw DIDResolutionError.malformedKey
            }
            let x963 = publicKey.x963Representation
            jwk = PublicJWK(
                kty: "EC",
                crv: "P-256",
                x: Data(x963[1 ..< 33]).base64URLEncodedString(),
                y: Data(x963[33 ..< 65]).base64URLEncodedString()
            )
        case Self.jwkJCSMultiCodec:
            let data = Data(decoded.dropFirst(offset))
            guard let decodedJWK = try? JSONDecoder().decode(PublicJWK.self, from: data),
                  decodedJWK.kty == "EC",
                  decodedJWK.crv == "P-256",
                  decodedJWK.y != nil else {
                throw DIDResolutionError.unsupportedKeyType
            }
            jwk = decodedJWK
        default:
            throw DIDResolutionError.unsupportedKeyType
        }
        let methodID = "\(did)#\(identifier)"
        return DIDDocument(
            id: did,
            verificationMethod: [
                DIDVerificationMethod(
                    id: methodID,
                    type: "JsonWebKey2020",
                    controller: did,
                    publicKeyJwk: jwk
                ),
            ],
            authentication: [methodID],
            assertionMethod: [methodID]
        )
    }

    public func derive(publicKeyX963: Data) throws -> String {
        guard publicKeyX963.count == 65, publicKeyX963.first == 0x04 else {
            throw DIDResolutionError.malformedKey
        }
        let validated: P256.Signing.PublicKey
        do {
            validated = try P256.Signing.PublicKey(x963Representation: publicKeyX963)
        } catch {
            throw DIDResolutionError.malformedKey
        }
        let representation = validated.x963Representation
        let x = representation[1 ..< 33]
        let yLast = representation[64]
        var compressed = Data([yLast.isMultiple(of: 2) ? 0x02 : 0x03])
        compressed.append(contentsOf: x)
        var bytes = Varint.encode(Self.p256Multicodec)
        bytes.append(contentsOf: compressed)
        return "did:key:\(Base58BTC.encode(bytes))"
    }
}

private enum Varint {
    static func encode(_ value: Int) -> [UInt8] {
        var value = value
        var output: [UInt8] = []
        repeat {
            var byte = UInt8(value & 0x7f)
            value >>= 7
            if value != 0 { byte |= 0x80 }
            output.append(byte)
        } while value != 0
        return output
    }

    static func decode(_ bytes: [UInt8]) throws -> (Int, Int) {
        var value = 0
        var shift = 0
        for (index, byte) in bytes.prefix(5).enumerated() {
            value |= Int(byte & 0x7f) << shift
            if byte & 0x80 == 0 { return (value, index + 1) }
            shift += 7
        }
        throw DIDResolutionError.malformedKey
    }
}

private enum Base58BTC {
    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

    static func encode(_ bytes: [UInt8]) -> String {
        var digits = [UInt8](repeating: 0, count: bytes.count * 138 / 100 + 1)
        var length = 0
        for byte in bytes {
            var carry = Int(byte)
            var index = 0
            while index < length || carry != 0 {
                carry += 256 * Int(digits[index])
                digits[index] = UInt8(carry % 58)
                carry /= 58
                index += 1
            }
            length = index
        }
        let zeroes = bytes.prefix { $0 == 0 }.count
        let body = digits.prefix(length).reversed().map { alphabet[Int($0)] }
        return "z" + String(repeating: "1", count: zeroes) + String(body)
    }

    static func decode(_ value: String) throws -> [UInt8] {
        guard value.utf8.count <= 248, value.first == "z" else {
            throw DIDResolutionError.malformedKey
        }
        let input = value.dropFirst()
        var bytes = [UInt8](repeating: 0, count: input.count * 733 / 1000 + 1)
        var length = 0
        for character in input {
            guard let alphabetIndex = alphabet.firstIndex(of: character) else {
                throw DIDResolutionError.malformedKey
            }
            var carry = alphabetIndex
            var index = 0
            while index < length || carry != 0 {
                carry += 58 * Int(bytes[index])
                bytes[index] = UInt8(carry % 256)
                carry /= 256
                index += 1
            }
            length = index
        }
        let zeroes = input.prefix { $0 == "1" }.count
        return Array(repeating: 0, count: zeroes) + bytes.prefix(length).reversed()
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }
}
