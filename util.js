module.exports = {
    logSize: value => {
        const valueBase64 = value.save();
        const size = valueBase64.length / 1e6;
        console.log('MB:', size);
        return size;
    },

    logCipher: (cipher, encoder, decryptor) => {
        const result = encoder.decode(decryptor.decrypt(cipher));
        console.log('cipher first value:', result[0]);
        return result;
    },

    logPlain: (cipher, encoder) => {
        const result = encoder.decode(cipher)[0];
        console.log('plain first value:', result);
        return result;
    },

    logChainIndex: (cipher, context) => {
        const index = context.getContextData(cipher.parmsId).chainIndex;
        console.log('this value is at chain index:', index);
        return index;
    },

    logScale: value => {
        const scale = Math.log2(value.scale);
        console.log('this value scale: ', scale);
        return scale;
    },

    logParameters: (context, seal) => {
        const contextData = context.keyContextData;
        let schemeName = null;

        switch (contextData.parms.scheme) {
            case seal.SchemeType.bfv:
                schemeName = 'BFV';
                break;
            case seal.SchemeType.ckks:
                schemeName = 'CKKS';
                break;
            case seal.SchemeType.bgv:
                schemeName = 'BGV';
                break;
            default:
                throw new Error('unsupported scheme');
        }

        console.log('/');
        console.log('| Encryption parameters:');
        console.log(`| Scheme: ${schemeName}:`);
        console.log(`| PolyModulusDegree: ${contextData.parms.polyModulusDegree}`);

        let bitCount = '(';
        contextData.parms.coeffModulus.forEach((coeff, i) => {
            bitCount += ` ${seal.Modulus(coeff).bitCount}`;
            if (contextData.parms.coeffModulus.length - 1 != i) {
                bitCount += ` +`;
            }
        });
        bitCount += ' )';

        console.log(`| CoeffModulus size: ${contextData.totalCoeffModulusBitCount} ${bitCount}`);

        const parmsValue = {
            scheme: schemeName,
            polyModulus: contextData.parms.polyModulusDegree,
            coeffModulus: contextData.totalCoeffModulusBitCount,
        };

        if (contextData.parms.scheme == seal.SchemeType.bfv) {
            console.log(`| PlainModulus: ${contextData.parms.plainModulus.value}`);
            parmsValue.plainModulus = Number(contextData.parms.plainModulus.value);
        }
        console.log(
            `| MaxCoeffModulus size: ${seal.CoeffModulus.MaxBitCount(
                contextData.parms.polyModulusDegree,
            )}`,
        );
        console.log('\\');

        return parmsValue;
    },
};
