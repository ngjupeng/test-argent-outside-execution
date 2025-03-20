import { KeyPair, SignerType, signerTypeToCustomEnum } from "./signer";
import * as utils from "@noble/curves/abstract/utils";
import { p256 as secp256r1 } from "@noble/curves/p256";
import { secp256k1 } from "@noble/curves/secp256k1";
import { Signature as EthersSignature, Wallet, keccak256, toUtf8Bytes } from "ethers";
import {
  Abi,
  Account,
  AccountInterface,
  AllowArray,
  BigNumberish,
  CairoCustomEnum,
  CairoOption,
  CairoOptionVariant,
  Call,
  CallData,
  Calldata,
  DeclareSignerDetails,
  DeployAccountContractPayload,
  DeployAccountSignerDetails,
  DeployContractResponse,
  FeeEstimate,
  InvocationsSignerDetails,
  InvokeFunctionResponse,
  RPC,
  Signature,
  SignerInterface,
  TransactionType,
  UniversalDetails,
  V2DeclareSignerDetails,
  V2DeployAccountSignerDetails,
  V2InvocationsSignerDetails,
  V3DeclareSignerDetails,
  V3DeployAccountSignerDetails,
  V3InvocationsSignerDetails,
  ec,
  encode,
  hash,
  num,
  shortString,
  stark,
  transaction,
  typedData,
  uint256,
} from "starknet";

export type NormalizedSecpSignature = { r: bigint; s: bigint; yParity: boolean };

export function normalizeSecpR1Signature(signature: {
  r: bigint;
  s: bigint;
  recovery: number;
}): NormalizedSecpSignature {
  return normalizeSecpSignature(secp256r1, signature);
}

export function normalizeSecpK1Signature(signature: {
  r: bigint;
  s: bigint;
  recovery: number;
}): NormalizedSecpSignature {
  return normalizeSecpSignature(secp256k1, signature);
}

export function normalizeSecpSignature(
  curve: typeof secp256r1 | typeof secp256k1,
  signature: { r: bigint; s: bigint; recovery: number },
): NormalizedSecpSignature {
  let s = signature.s;
  let yParity = signature.recovery !== 0;
  if (s > curve.CURVE.n / 2n) {
    s = curve.CURVE.n - s;
    yParity = !yParity;
  }
  return { r: signature.r, s, yParity };
}

export class EthKeyPair extends KeyPair {
  private ethAddress: bigint;
  private signCallback: (messageHash: string) => Promise<{ r: bigint; s: bigint; yParity: boolean }>;

  constructor(
    address: bigint,
    signCallback: (messageHash: string) => Promise<{ r: bigint; s: bigint; yParity: boolean }>,
  ) {
    super();

    this.ethAddress = address;
    this.signCallback = signCallback;
  }

  public get address(): bigint {
    return BigInt(this.ethAddress);
  }

  public get guid(): bigint {
    return BigInt(hash.computePoseidonHash(shortString.encodeShortString("Secp256k1 Signer"), this.address));
  }

  public get storedValue(): bigint {
    throw new Error("Not implemented yet");
  }

  public get signer(): CairoCustomEnum {
    return signerTypeToCustomEnum(SignerType.Secp256k1, { signer: this.address });
  }

  public async signRaw(messageHash: string): Promise<string[]> {
    console.log("messageHash", messageHash);
    const signature = await this.signCallback(messageHash);

    const callData = CallData.compile([
      signerTypeToCustomEnum(SignerType.Secp256k1, {
        pubkeyHash: this.address,
        r: uint256.bnToUint256(signature.r),
        s: uint256.bnToUint256(signature.s),
        y_parity: signature.yParity,
      }),
    ]);
    // return callData;
    return callData;
  }
}

export class EthKeyPairRandom extends KeyPair {
  pk: bigint;
  allowLowS?: boolean;

  constructor(pk?: string | bigint, allowLowS?: boolean) {
    super();

    if (pk == undefined) {
      pk = Wallet.createRandom().privateKey;
    }
    if (typeof pk === "string") {
      pk = BigInt(pk);
    }
    this.pk = pk;
    this.allowLowS = allowLowS;
  }

  public get address(): bigint {
    return BigInt(new Wallet("0x" + padTo32Bytes(num.toHex(this.pk))).address);
  }

  public get guid(): bigint {
    return BigInt(hash.computePoseidonHash(shortString.encodeShortString("Secp256k1 Signer"), this.address));
  }

  public get storedValue(): bigint {
    throw new Error("Not implemented yet");
  }

  public get signer(): CairoCustomEnum {
    return signerTypeToCustomEnum(SignerType.Secp256k1, { signer: this.address });
  }

  public async signRaw(messageHash: string): Promise<string[]> {
    // \x19Ethereum Signed Message:\n{messageHah.length}messagehash

    // Create the Ethereum signed message
    const messagePrefix = "\x19Ethereum Signed Message:\n";
    const messageLength = messageHash.length.toString();
    const message = messagePrefix + messageLength + messageHash;

    // Convert the message to UTF-8 bytes and then hash it
    const messageBytes = toUtf8Bytes(message);
    const keccak = keccak256(messageBytes);

    console.log("KECCAK", keccak);

    const signature = normalizeSecpK1Signature(
      secp256k1.sign(padTo32Bytes(keccak), this.pk, {
        lowS: this.allowLowS,
      }),
    );

    // verify signature

    console.log("SIGNATURE", signature);

    // const signatureHex =
    //   "0x" +
    //   padTo32Bytes(signature.r.toString(16)) +
    //   padTo32Bytes(signature.s.toString(16)) +
    //   (signature.yParity ? "01" : "00");

    // console.log("Signature hex:", signatureHex);
    // console.log(
    //   "Random signature components:",
    //   secp256k1.sign(padTo32Bytes(messageHash), this.pk, { lowS: this.allowLowS }),
    // );
    // const callData = CallData.compile([
    //   signerTypeToCustomEnum(SignerType.Secp256k1, {
    //     pubkeyHash: this.address,
    //     r: uint256.bnToUint256(signature.r),
    //     s: uint256.bnToUint256(signature.s),
    //     y_parity: signature.yParity,
    //   }),
    // ]);
    // return callData;
    return [];
  }
}

export class Eip191KeyPairMetamask extends KeyPair {
  private ethAddress: bigint;
  private signCallback: (messageHash: Uint8Array) => Promise<{ r: bigint; s: bigint; yParity: boolean }>;

  constructor(
    address: bigint,
    signCallback: (messageHash: Uint8Array) => Promise<{ r: bigint; s: bigint; yParity: boolean }>,
  ) {
    super();
    this.ethAddress = address;
    this.signCallback = signCallback;
  }

  public get address(): bigint {
    return BigInt(this.ethAddress);
  }

  public get guid(): bigint {
    return BigInt(hash.computePoseidonHash(shortString.encodeShortString("Eip191 Signer"), this.address));
  }

  public get storedValue(): bigint {
    throw new Error("Not implemented yet");
  }

  public get signer(): CairoCustomEnum {
    return signerTypeToCustomEnum(SignerType.Eip191, { signer: this.address });
  }

  public async signRaw(messageHash: string): Promise<string[]> {
    console.log("signRaw called with messageHash:", messageHash);

    messageHash = "0x" + padTo32Bytes(messageHash);

    // Convert to bytes array before signing, matching the contract's verification
    const messageBytes = num.hexToBytes(messageHash);
    console.log("Prepared message bytes:", messageBytes);
    const signature = await this.signCallback(messageBytes);
    const callData = CallData.compile([
      signerTypeToCustomEnum(SignerType.Eip191, {
        ethAddress: this.address,
        r: uint256.bnToUint256(signature.r),
        s: uint256.bnToUint256(signature.s),
        y_parity: signature.yParity,
      }),
    ]);
    return callData;
    // return [];
  }
}

export class Eip191KeyPairMetamaskWithSignature extends KeyPair {
  private ethAddress: bigint;
  private calldata: string[];

  constructor(address: bigint, calldata: string[]) {
    super();
    this.ethAddress = address;
    this.calldata = calldata;
  }

  public get address(): bigint {
    return BigInt(this.ethAddress);
  }

  public get guid(): bigint {
    return BigInt(hash.computePoseidonHash(shortString.encodeShortString("Eip191 Signer"), this.address));
  }

  public get storedValue(): bigint {
    throw new Error("Not implemented yet");
  }

  public get signer(): CairoCustomEnum {
    return signerTypeToCustomEnum(SignerType.Eip191, { signer: this.address });
  }

  public async signRaw(messageHash: string): Promise<string[]> {
    return this.calldata;
    // return [];
  }
}

export class Eip191KeyPair extends KeyPair {
  pk: string;

  constructor(pk?: string | bigint) {
    super();
    this.pk = pk ? "0x" + padTo32Bytes(num.toHex(pk)) : Wallet.createRandom().privateKey;
  }

  public get address() {
    return BigInt(new Wallet(this.pk).address);
  }

  public get guid(): bigint {
    return BigInt(hash.computePoseidonHash(shortString.encodeShortString("Eip191 Signer"), this.address));
  }

  public get storedValue(): bigint {
    throw new Error("Not implemented yet");
  }

  public get signer(): CairoCustomEnum {
    return signerTypeToCustomEnum(SignerType.Eip191, { signer: this.address });
  }

  public async signRaw(messageHash: string): Promise<string[]> {
    const ethSigner = new Wallet(this.pk);
    messageHash = "0x" + padTo32Bytes(messageHash);
    const ethersSignature = EthersSignature.from(ethSigner.signMessageSync(num.hexToBytes(messageHash)));
    console.log("ethersSignature with pk", ethersSignature, num.hexToBytes(messageHash));
    const signature = normalizeSecpK1Signature({
      r: BigInt(ethersSignature.r),
      s: BigInt(ethersSignature.s),
      recovery: ethersSignature.yParity ? 1 : 0,
    });

    // console.log(
    //   "sign raw Eip191KeyPair",
    //   CallData.compile([
    //     signerTypeToCustomEnum(SignerType.Eip191, {
    //       ethAddress: this.address,
    //       r: uint256.bnToUint256(signature.r),
    //       s: uint256.bnToUint256(signature.s),
    //       y_parity: signature.yParity,
    //     }),
    //   ]),
    // );

    return CallData.compile([
      signerTypeToCustomEnum(SignerType.Eip191, {
        ethAddress: this.address,
        r: uint256.bnToUint256(signature.r),
        s: uint256.bnToUint256(signature.s),
        y_parity: signature.yParity,
      }),
    ]);

    return [];
  }
}

export class EstimateEip191KeyPair extends KeyPair {
  readonly address: bigint;

  constructor(address: bigint) {
    super();
    this.address = address;
  }

  public get privateKey(): string {
    throw new Error("EstimateEip191KeyPair does not have a private key");
  }

  public get guid(): bigint {
    throw new Error("Not implemented yet");
  }

  public get storedValue(): bigint {
    throw new Error("Not implemented yet");
  }

  public get signer(): CairoCustomEnum {
    return signerTypeToCustomEnum(SignerType.Eip191, { signer: this.address });
  }

  public async signRaw(messageHash: string): Promise<string[]> {
    return CallData.compile([
      signerTypeToCustomEnum(SignerType.Eip191, {
        ethAddress: this.address,
        r: uint256.bnToUint256("0x1556a70d76cc452ae54e83bb167a9041f0d062d000fa0dcb42593f77c544f647"),
        s: uint256.bnToUint256("0x1643d14dbd6a6edc658f4b16699a585181a08dba4f6d16a9273e0e2cbed622da"),
        y_parity: false,
      }),
    ]);
  }
}

export class Secp256r1KeyPair extends KeyPair {
  pk: bigint;
  private allowLowS?: boolean;

  constructor(pk?: string | bigint, allowLowS?: boolean) {
    super();
    this.pk = BigInt(pk ? `${pk}` : Wallet.createRandom().privateKey);
    this.allowLowS = allowLowS;
  }

  public get publicKey() {
    const publicKey = secp256r1.getPublicKey(this.pk).slice(1);
    return uint256.bnToUint256("0x" + utils.bytesToHex(publicKey));
  }

  public get guid(): bigint {
    return BigInt(
      hash.computePoseidonHashOnElements([
        shortString.encodeShortString("Secp256r1 Signer"),
        this.publicKey.low,
        this.publicKey.high,
      ]),
    );
  }

  public get storedValue(): bigint {
    throw new Error("Not implemented yet");
  }

  public get signer() {
    return signerTypeToCustomEnum(SignerType.Secp256r1, { signer: this.publicKey });
  }

  public async signRaw(messageHash: string): Promise<string[]> {
    messageHash = padTo32Bytes(messageHash);
    const signature = normalizeSecpR1Signature(secp256r1.sign(messageHash, this.pk, { lowS: this.allowLowS }));
    return CallData.compile([
      signerTypeToCustomEnum(SignerType.Secp256r1, {
        pubkey: this.publicKey,
        r: uint256.bnToUint256(signature.r),
        s: uint256.bnToUint256(signature.s),
        y_parity: signature.yParity,
      }),
    ]);
  }
}

export abstract class RawSignerMultisig implements SignerInterface {
  abstract signRaw(messageHash: string): Promise<{ messageBytes: Uint8Array; signature: string }>;

  public async getPubKey(): Promise<string> {
    throw new Error("This signer allows multiple public keys");
  }

  public async signMessage(typedDataArgument: typeof typedData.TypedData, accountAddress: string): Promise<any> {
    const messageHash = typedData.getMessageHash(typedDataArgument, accountAddress);
    return this.signRaw(messageHash);
  }

  public async signTransaction(transactions: Call[], details: InvocationsSignerDetails): Promise<any> {
    const compiledCalldata = transaction.getExecuteCalldata(transactions, details.cairoVersion);
    let msgHash;

    // TODO: How to do generic union discriminator for all like this
    if (Object.values(RPC.ETransactionVersion2).includes(details.version as any)) {
      const det = details as V2InvocationsSignerDetails;
      msgHash = hash.calculateInvokeTransactionHash({
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
      });
      // console.log("Sign transaction hash v2", msgHash, {
      //   ...det,
      //   senderAddress: det.walletAddress,
      //   compiledCalldata,
      //   version: det.version,
      // });
    } else if (Object.values(RPC.ETransactionVersion3).includes(details.version as any)) {
      const det = details as V3InvocationsSignerDetails;
      msgHash = hash.calculateInvokeTransactionHash({
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
      // console.log("Sign transaction hash v3", msgHash);
    } else {
      throw new Error("unsupported signTransaction version");
    }
    return await this.signRaw(msgHash);
  }

  public async signDeployAccountTransaction(details: DeployAccountSignerDetails): Promise<any> {
    const compiledConstructorCalldata = CallData.compile(details.constructorCalldata);
    /*     const version = BigInt(details.version).toString(); */
    let msgHash;

    if (Object.values(RPC.ETransactionVersion2).includes(details.version as any)) {
      const det = details as V2DeployAccountSignerDetails;
      msgHash = hash.calculateDeployAccountTransactionHash({
        ...det,
        salt: det.addressSalt,
        constructorCalldata: compiledConstructorCalldata,
        version: det.version,
      });
    } else if (Object.values(RPC.ETransactionVersion3).includes(details.version as any)) {
      const det = details as V3DeployAccountSignerDetails;
      msgHash = hash.calculateDeployAccountTransactionHash({
        ...det,
        salt: det.addressSalt,
        compiledConstructorCalldata,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error(`unsupported signDeployAccountTransaction version: ${details.version}}`);
    }

    return await this.signRaw(msgHash);
  }

  public async signDeclareTransaction(
    // contractClass: ContractClass,  // Should be used once class hash is present in ContractClass
    details: DeclareSignerDetails,
  ): Promise<any> {
    let msgHash;

    if (Object.values(RPC.ETransactionVersion2).includes(details.version as any)) {
      const det = details as V2DeclareSignerDetails;
      msgHash = hash.calculateDeclareTransactionHash({
        ...det,
        version: det.version,
      });
    } else if (Object.values(RPC.ETransactionVersion3).includes(details.version as any)) {
      const det = details as V3DeclareSignerDetails;
      msgHash = hash.calculateDeclareTransactionHash({
        ...det,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error("unsupported signDeclareTransaction version");
    }

    return await this.signRaw(msgHash);
  }
}

export abstract class RawStrkSignerMultisig implements SignerInterface {
  abstract signMessageOwn(typedDataArgument: typeof typedData.TypedData): Promise<any>;
  abstract signRaw(messageHash: string): Promise<string[]>;

  public async getPubKey(): Promise<string> {
    throw new Error("This signer allows multiple public keys");
  }

  public async signMessage(typedDataArgument: typeof typedData.TypedData, accountAddress: string): Promise<any> {
    console.log("DID I TRIGGERED?");
    return this.signMessageOwn(typedDataArgument);
  }

  public async signTransaction(transactions: Call[], details: InvocationsSignerDetails): Promise<any> {
    const compiledCalldata = transaction.getExecuteCalldata(transactions, details.cairoVersion);
    let msgHash;

    // TODO: How to do generic union discriminator for all like this
    if (Object.values(RPC.ETransactionVersion2).includes(details.version as any)) {
      const det = details as V2InvocationsSignerDetails;
      msgHash = hash.calculateInvokeTransactionHash({
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
      });
      // console.log("Sign transaction hash v2", msgHash, {
      //   ...det,
      //   senderAddress: det.walletAddress,
      //   compiledCalldata,
      //   version: det.version,
      // });
    } else if (Object.values(RPC.ETransactionVersion3).includes(details.version as any)) {
      const det = details as V3InvocationsSignerDetails;
      msgHash = hash.calculateInvokeTransactionHash({
        ...det,
        senderAddress: det.walletAddress,
        compiledCalldata,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
      // console.log("Sign transaction hash v3", msgHash);
    } else {
      throw new Error("unsupported signTransaction version");
    }
    return null;
  }

  public async signDeployAccountTransaction(details: DeployAccountSignerDetails): Promise<any> {
    const compiledConstructorCalldata = CallData.compile(details.constructorCalldata);
    /*     const version = BigInt(details.version).toString(); */
    let msgHash;

    if (Object.values(RPC.ETransactionVersion2).includes(details.version as any)) {
      const det = details as V2DeployAccountSignerDetails;
      msgHash = hash.calculateDeployAccountTransactionHash({
        ...det,
        salt: det.addressSalt,
        constructorCalldata: compiledConstructorCalldata,
        version: det.version,
      });
    } else if (Object.values(RPC.ETransactionVersion3).includes(details.version as any)) {
      const det = details as V3DeployAccountSignerDetails;
      msgHash = hash.calculateDeployAccountTransactionHash({
        ...det,
        salt: det.addressSalt,
        compiledConstructorCalldata,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error(`unsupported signDeployAccountTransaction version: ${details.version}}`);
    }

    return null;
  }

  public async signDeclareTransaction(
    // contractClass: ContractClass,  // Should be used once class hash is present in ContractClass
    details: DeclareSignerDetails,
  ): Promise<any> {
    let msgHash;

    if (Object.values(RPC.ETransactionVersion2).includes(details.version as any)) {
      const det = details as V2DeclareSignerDetails;
      msgHash = hash.calculateDeclareTransactionHash({
        ...det,
        version: det.version,
      });
    } else if (Object.values(RPC.ETransactionVersion3).includes(details.version as any)) {
      const det = details as V3DeclareSignerDetails;
      msgHash = hash.calculateDeclareTransactionHash({
        ...det,
        version: det.version,
        nonceDataAvailabilityMode: stark.intDAM(det.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: stark.intDAM(det.feeDataAvailabilityMode),
      });
    } else {
      throw new Error("unsupported signDeclareTransaction version");
    }

    return null;
  }
}
export abstract class KeyPairMultisig extends RawSignerMultisig {
  abstract get signer(): CairoCustomEnum;
  abstract get guid(): bigint;
  abstract get storedValue(): bigint;

  public get compiledSigner(): Calldata {
    return CallData.compile([this.signer]);
  }

  public get signerAsOption() {
    return new CairoOption(CairoOptionVariant.Some, {
      signer: this.signer,
    });
  }
  public get compiledSignerAsOption() {
    return CallData.compile([this.signerAsOption]);
  }
}

export class Eip191KeyPairMultisigMetamask extends KeyPairMultisig {
  private ethAddress: bigint;
  private signCallback: (messageHash: Uint8Array) => Promise<{ messageBytes: Uint8Array; signature: string }>;

  constructor(
    address: bigint,
    signCallback: (messageHash: Uint8Array) => Promise<{ messageBytes: Uint8Array; signature: string }>,
  ) {
    super();
    this.ethAddress = address;
    this.signCallback = signCallback;
  }

  public get address(): bigint {
    return BigInt(this.ethAddress);
  }

  public get guid(): bigint {
    return BigInt(hash.computePoseidonHash(shortString.encodeShortString("Eip191 Signer"), this.address));
  }

  public get storedValue(): bigint {
    throw new Error("Not implemented yet");
  }

  public get signer(): CairoCustomEnum {
    return signerTypeToCustomEnum(SignerType.Eip191, { signer: this.address });
  }

  public async signRaw(messageHash: string): Promise<{ messageBytes: Uint8Array; signature: string }> {
    console.log("signRaw called with messageHash:", messageHash);

    messageHash = "0x" + padTo32Bytes(messageHash);

    // Convert to bytes array before signing, matching the contract's verification
    const messageBytes = num.hexToBytes(messageHash);
    const signature = await this.signCallback(messageBytes);
    // const callData = CallData.compile([
    //   signerTypeToCustomEnum(SignerType.Eip191, {
    //     ethAddress: this.address,
    //     r: uint256.bnToUint256(signature.r),
    //     s: uint256.bnToUint256(signature.s),
    //     y_parity: signature.yParity,
    //   }),
    // ]);
    return signature;
    // return [];
  }
}

export class BraavosStrkKeyPairMultisigMetamask extends RawStrkSignerMultisig {
  private strkAddress: string;
  private strkAccount: AccountInterface;
  private publicKey: bigint;

  constructor(address: string, publicKey: bigint, strkAccount: AccountInterface) {
    super();
    this.strkAddress = address;
    this.strkAccount = strkAccount;
    this.publicKey = publicKey;
  }

  public get address(): bigint {
    return BigInt(this.strkAddress);
  }

  public get guid(): bigint {
    return BigInt(hash.computePoseidonHash(shortString.encodeShortString("Starknet Signer"), this.publicKey));
  }

  public get storedValue(): bigint {
    throw new Error("Not implemented yet");
  }

  public get signer(): CairoCustomEnum {
    return signerTypeToCustomEnum(SignerType.Starknet, { signer: this.publicKey });
  }

  public async signMessageOwn(typedDataArgument: typeof typedData.TypedData): Promise<any> {
    const signature = await this.strkAccount.signMessage(typedDataArgument);
    return signature;
  }

  public async signRaw(typedDataArgument: typeof typedData.TypedData | string): Promise<string[]> {
    const signature = await this.strkAccount.signMessage(typedDataArgument);
    return signature as any;
  }
}

export function padTo32Bytes(hexString: string): string {
  if (hexString.startsWith("0x")) {
    hexString = hexString.slice(2);
  }
  if (hexString.length < 64) {
    hexString = "0".repeat(64 - hexString.length) + hexString;
  }
  return hexString;
}

export const randomEip191KeyPair = () => new Eip191KeyPair();
export const randomSecp256r1KeyPair = () => new Secp256r1KeyPair();
export const randomEthKeyPair = () => new EthKeyPairRandom();
