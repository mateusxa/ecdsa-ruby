module EllipticCurve

    module PrivateKeyConstants

        def self._pemTemplate
            return "-----BEGIN EC PRIVATE KEY-----\n{content}\n-----END EC PRIVATE KEY-----"
        end

        def self.DerFieldType 
            return Utils::Der::DerFieldType.new()
        end

    end

    class PrivateKey

        attr_accessor :curve, :secret

        def initialize(curve=Curve.secp256k1, secret=nil)
            @curve = curve
            @secret = secret ? secret : Utils::RandomInteger.between(1, @curve.n - 1)
        end

        def publicKey
            curve = @curve
            publicPoint = Math.multiply(
                curve.g,
                @secret,
                curve.n,
                curve.a,
                curve.p
            )
            return PublicKey.new(publicPoint, curve)
        end

        def toString
            return Utils::Binary.hexFromInt(@secret)
        end

        def toDer
            publicKeyString = self.publicKey.toString(true)
            hexadecimal = Utils::Der.encodeConstructed(
                Utils::Der.encodePrimitive(PrivateKeyConstants.DerFieldType.integer, 1),
                Utils::Der.encodePrimitive(PrivateKeyConstants.DerFieldType.octetString, Utils::Binary.hexFromInt(@secret)),
                Utils::Der.encodePrimitive(PrivateKeyConstants.DerFieldType.oidContainer, Utils::Der.encodePrimitive(PrivateKeyConstants.DerFieldType.object, @curve.oid)),
                Utils::Der.encodePrimitive(PrivateKeyConstants.DerFieldType.publicKeyPointContainer, Utils::Der.encodePrimitive(PrivateKeyConstants.DerFieldType.bitString, publicKeyString))
            )
            return Utils::Binary.byteStringFromHex(hexadecimal)
        end

        def toPem
            der = self.toDer()
            return Utils::Pem.create(Utils::Binary.base64FromByteString(der), PrivateKeyConstants._pemTemplate)
        end

        def self.fromPem(string)
            privateKeyPem = Utils::Pem.getContent(string, PrivateKeyConstants._pemTemplate)
            return self.fromDer(Utils::Binary.byteStringFromBase64(privateKeyPem))
        end

        def self.fromDer(string)
            hexadecimal = Utils::Binary.hexFromByteString(string)
            privateKeyFlag, secretHex, curveData, publicKeyString = Utils::Der.parse(hexadecimal)[0]
            if privateKeyFlag != 1
                raise Exception.new("Private keys should start with a '1' flag, but a '#{privateKeyFlag}' was found instead")
            end
            curve = Curve.getbyOid(curveData[0])
            privateKey = self.fromString(secretHex, curve)
            if privateKey.publicKey.toString(true) != publicKeyString[0]
                raise Exception.new("The public key described inside the private key file doesn't match the actual public key of the pair")
            end
            return privateKey
        end

        def self.fromString(string, curve=Curve.secp256k1)
            return PrivateKey.new(curve, Utils::Binary.intFromHex(string))
        end

    end

end
