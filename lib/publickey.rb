module EllipticCurve

    module PublicKeyConstants

        def self._pemTemplate
            return "-----BEGIN PUBLIC KEY-----\n{content}\n-----END PUBLIC KEY-----"
        end

        def self._ecdsaPublicKeyOid
            return [1, 2, 840, 10045, 2, 1]
        end

        def self.DerFieldType 
            return Utils::Der::DerFieldType.new()
        end

    end

    class PublicKey

        attr_accessor :point, :curve

        def initialize(point, curve)
            @point = point
            @curve = curve
        end
        
        def toString encoded=false
            baseLength = 2 * @curve.length

            xHex = Utils::Binary.hexFromInt(@point.x).rjust(baseLength, "0")
            yHex = Utils::Binary.hexFromInt(@point.y).rjust(baseLength, "0")
            string = xHex + yHex
            if encoded 
                return "0004" + string
            end
            return string
        end

        def toDer
            @hexadecimal = Utils::Der.encodeConstructed(
                Utils::Der.encodeConstructed(
                    Utils::Der.encodePrimitive(PublicKeyConstants.DerFieldType.object, PublicKeyConstants._ecdsaPublicKeyOid),
                    Utils::Der.encodePrimitive(PublicKeyConstants.DerFieldType.object, @curve.oid)
                ),
                Utils::Der.encodePrimitive(PublicKeyConstants.DerFieldType.bitString, self.toString(true))       
            )
            return Utils::Binary.byteStringFromHex(@hexadecimal)
        end

        def toPem
            der = self.toDer()
            return Utils::Pem.create(Utils::Binary.base64FromByteString(der), PublicKeyConstants._pemTemplate)
        end

        def self.fromPem(string)
            
            publicKeyPem = Utils::Pem.getContent(string, PublicKeyConstants._pemTemplate)
            
            return self.fromDer(Utils::Binary.byteStringFromBase64(publicKeyPem))
        end

        def self.fromDer(string)
            hexadecimal = Utils::Binary.hexFromByteString(string)
            curveData, pointString = Utils::Der.parse(hexadecimal)[0]
            publicKeyOid, curveOid = curveData
            if publicKeyOid != PublicKeyConstants._ecdsaPublicKeyOid
                raise Exception.new("The Public Key Object Identifier (OID) should be #{PublicKeyConstants._ecdsaPublicKeyOid}, but #{publicKeyOid} was found instead")
            end
            curve = Curve.getbyOid(curveOid)
            return self.fromString(pointString, curve)
        end

        def self.fromString(string, curve=Curve.secp256k1, validatePoint=true)
            baseLength = 2 * curve.length
            if string.length > 2 * baseLength and string[0..3] == "0004"
                string = string[4..-1]
            end

            xs = string[0..baseLength - 1]
            ys = string[baseLength..-1]

            p = Point.new(
                Utils::Binary.intFromHex(xs), 
                Utils::Binary.intFromHex(ys)
            )

            publicKey = PublicKey.new(p, curve)
            if not validatePoint
                return publicKey
            end
            if p.isAtInfinity()
                raise Exception.new("Public key point at infinity")
            end
            if not curve.contains(p)
                raise Exception.new("Point (#{p.x}, #{p.y}) is not valid for curve #{curve.name}")
            end
            if not Math.multiply(p, curve.n, curve.n, curve.a, curve.p).isAtInfinity()
                raise Exception.new("Point (#{p.x}, #{p.y}) * #{curve.name}.n is not at infinity")
            end
            
            return publicKey
        end

    end

end
