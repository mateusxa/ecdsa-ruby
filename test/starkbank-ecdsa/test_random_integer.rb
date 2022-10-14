describe EllipticCurve do
    it 'test many' do
        min = 0
        max = (2 ** 4) + 1
        results = {}
        success = true

        (0..1000000).each { |i|

            integer = EllipticCurve::Utils::RandomInteger.between(min, max)
        
            key = integer
        
            if (results.key? key) then
                results[key] = results[key] + 1
            else 
                results[key] = 1
            end
            success = success and (integer >= min and integer <= max)
        }
        
        # Verify if all numbers in the range were generated
        (min..max).each { |i|
            key = i
            success = success and (results[key] > 0)
        }

        expect(success).must_equal true
    end
end
