const fs = require('fs');

const {
    logChainIndex,
    logCipher,
    logSize,
    logParameters,
    logScale,
    logPlain,
} = require('./util.js');

async function main() {
    const seal = await require('node-seal')();

    const schemeType = seal.SchemeType.ckks;
    const securityLevel = seal.SecurityLevel.none;
    const polyModulusDegree = Math.pow(2, 14);
    const bitSizes = [60, 40, 40, 40, 40, 40, 40, 60];
    const scale = Math.pow(2, 40);

    const parms = seal.EncryptionParameters(schemeType);

    // Set the PolyModulusDegree
    parms.setPolyModulusDegree(polyModulusDegree);

    // Create a suitable set of CoeffModulus primes
    parms.setCoeffModulus(seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes)));

    const context = seal.Context(
        parms, // Encryption Parameters
        true, // ExpandModChain
        securityLevel, // Enforce a security level
    );

    logParameters(context, seal);

    if (!context.parametersSet()) {
        throw new Error(
            'Could not set the parameters in the given context. Please try different encryption parameters.',
        );
    }

    const encoder = seal.CKKSEncoder(context);
    const keyGenerator = seal.KeyGenerator(context);
    const publicKey = keyGenerator.createPublicKey();
    const secretKey = keyGenerator.secretKey();
    const relinKey = keyGenerator.createRelinKeys();
    const encryptor = seal.Encryptor(context, publicKey);
    const decryptor = seal.Decryptor(context, secretKey);
    const evaluator = seal.Evaluator(context);

    // Create data to be encrypted
    const d = 3;
    const x = 100;
    const min = 0;
    const max = 10000;
    const array_x = Float64Array.from({ length: encoder.slotCount }, () => x);
    const array_y = Float64Array.from({ length: encoder.slotCount }, (_, i) => {
        if (i <= 1000) return i * -10;
        else return 0;
    });
    const array2 = Float64Array.from({ length: encoder.slotCount }, () => 2);
    const array1 = Float64Array.from({ length: encoder.slotCount }, () => 1);

    //Encode the Array
    const plainText_x = encoder.encode(array_x, scale);
    const plainText_y = encoder.encode(array_y, scale);

    // Encrypt the PlainText
    const cipherText_x = encryptor.encrypt(plainText_x);
    const cipherText_y = encryptor.encrypt(plainText_y);
    const scalePlain = encoder.encode(
        Float64Array.from({ length: encoder.slotCount }, () => 2 / max),
        scale,
    );

    logSize(cipherText_x);

    // Normailze f(x) = (x /10000 )* 2 = x/5000 = x * 0.0002
    evaluator.multiplyPlain(cipherText_x, scalePlain, cipherText_x);
    evaluator.relinearize(cipherText_x, relinKey);
    evaluator.rescaleToNext(cipherText_x, cipherText_x);
    cipherText_x.setScale(scale);

    evaluator.multiplyPlain(cipherText_y, scalePlain, cipherText_y);
    evaluator.relinearize(cipherText_y, relinKey);
    evaluator.rescaleToNext(cipherText_y, cipherText_y);
    cipherText_y.setScale(scale);

    // for (let j = 0; j < 3; j++) {
    const plain2 = encoder.encode(array2, scale);
    const plain1 = encoder.encode(array1, scale);

    const negativeCipher = evaluator.negate(cipherText_y);

    evaluator.plainModSwitchToNext(plain1, plain1);
    evaluator.plainModSwitchToNext(plain2, plain2);

    let a0Cipher = evaluator.addPlain(negativeCipher, plain2);
    let b0cipher = evaluator.addPlain(negativeCipher, plain1);
    let bnCipher = seal.CipherText();
    let anCipher = seal.CipherText();
    evaluator.cipherModSwitchToNext(a0Cipher, a0Cipher);

    for (let i = 0; i < d; i++) {
        evaluator.square(b0cipher, bnCipher);
        evaluator.relinearize(bnCipher, relinKey, bnCipher);
        evaluator.rescaleToNext(bnCipher, bnCipher);
        bnCipher.setScale(scale);

        evaluator.plainModSwitchToNext(plain1, plain1);
        evaluator.addPlain(bnCipher, plain1, anCipher);
        evaluator.multiply(anCipher, a0Cipher, anCipher);
        evaluator.relinearize(anCipher, relinKey, anCipher);
        evaluator.rescaleToNext(anCipher, anCipher);
        anCipher.setScale(scale);

        b0cipher = bnCipher;
        a0Cipher = anCipher.clone();
    }

    //     resultArray[j] = anCipher.clone();
    //     logCipher(resultArray[j], encoder, decryptor);
    // }

    // const resultCipher = resultArray.reduce((preCipher, currentCipher) => {
    //     return evaluator.add(preCipher, currentCipher);
    // });

    // const plain3 = encoder.encode(
    //     Float64Array.from({ length: encoder.slotCount }, () => 1 / 3),
    //     scale,
    // );

    // evaluator.plainModSwitchTo(plain3, resultCipher.parmsId, plain3);
    // evaluator.multiplyPlain(resultCipher, plain3, resultCipher);
    const resultCipher_y = anCipher;

    evaluator.cipherModSwitchTo(cipherText_x, resultCipher_y.parmsId, cipherText_x);
    evaluator.multiply(cipherText_x, resultCipher_y, cipherText_x);
    evaluator.relinearize(cipherText_x, relinKey);
    evaluator.rescaleToNext(cipherText_x, cipherText_x);
    cipherText_x.setScale(scale);

    logSize(cipherText_x);
    logChainIndex(cipherText_x, context);
    logScale(cipherText_x);
    let result = logCipher(cipherText_x, encoder, decryptor);

    let testResult = [];

    array_y.forEach((value, i) => {
        if (i <= 1000) {
            const x_test = (x / max) * 2;
            const y_test = (value / max) * 2;

            let a0 = 2 - y_test;
            let b0 = 1 - y_test;
            let an = 0;
            let bn = 0;

            for (let i = 0; i < d; i++) {
                bn = b0 ** 2;
                an = a0 * (1 + bn);
                a0 = an;
                b0 = bn;
            }
            const result_test = x_test * an;

            testResult[i] = result_test;
        }
    });

    const expectValue = [];
    array_y.forEach((value, i) => {
        if (i <= 1000) {
            expectValue[i] = x / value;
        }
    });

    let errPercents = [];

    expectValue.forEach((value, i) => {
        const errPercent = Math.abs((testResult[i] - value) / value) * 100;
        errPercents[i] = errPercent;
    });

    // console.log(`Except is: ${1 / y_test}, computed value: ${an}`);

    // // console.log('');
    // console.log('<<-----Result----->>');
    // // console.log('CKKS method: ', result);
    // console.log('Normal method: ', result_test);
    // console.log('Expected value:', x / y);

    const errPercentsCKKS = [];
    testResult = result;

    expectValue.forEach((value, i) => {
        const errPercent = Math.abs((testResult[i] - value) / value) * 100;
        errPercentsCKKS[i] = errPercent;
    });

    let stream = fs.createWriteStream(`xValueEqual${x}.csv`);
    stream.once('open', fd => {
        stream.write(`,Normal Error Percents,CKKS Error Percents\n`);
        Array.from({ length: 999 }).forEach((_, i) => {
            stream.write(`${array_y[i + 1]},${errPercents[i + 1]},${errPercentsCKKS[i + 1]}\n`);
        });
        stream.end();
    });

    // const newSteam = fs.createWriteStream(`xValueEqual${x}CKKS.csv`);
    // newSteam.once('open', fd => {
    //     newSteam.write(`y value,Error Percents\n`);
    //     Array.from({ length: 999 }).forEach((_, i) => {
    //         newSteam.write(`${array_y[i + 1]},${errPercents[i + 1]}\n`);
    //     });
    //     newSteam.end();
    // });
}

main();
