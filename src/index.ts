import {
    Connection,
    sendAndConfirmTransaction,
    Keypair,
    Transaction,
    SystemProgram,
    PublicKey,
    TransactionInstruction,
    Message,
    AccountMeta,
    sendAndConfirmRawTransaction,
    Signer,
  } from "@solana/web3.js";

  import {createAssociatedTokenAccountInstruction, getAssociatedTokenAddress, createTransferInstruction, transfer} from '@solana/spl-token'

import * as ed from '@noble/ed25519';
import * as base58 from 'bs58';
import { randomBytesSeed } from '@csquare/random-bytes-seed';
import { BN } from "bn.js";
//import { dksap, pubsc, pubsp, privsc, privsp, bytes1 } from "./constants.js";


const dksap = "3iUBKuvbRMPNLeF33QJHYia7ZBNDWqiccy35MXBRQd1f";



// Convert a byte array to a hex string
function bytesToHex(bytes: Uint8Array | number[]) {
  let hex: Array<string> = [];
  for (let i = 0; i < bytes.length; i++) {
      let current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
      hex.push((current >>> 4).toString(16));
      hex.push((current & 0xF).toString(16));
  }
  return hex.join("");
}



/**
 * Generates address to send stealth transaction to
 *
 * @export
 * @param {string} pubScanStr
 * @param {string} pubspendstr
 * @param {string} ephemprivstr should be from a randomly generated keypair, for security
 * @return {*}  {Promise<ed.Point>}
 */
export async function senderGenAddress (pubScanStr: string, pubspendstr: string, ephemprivstr: string) :Promise<ed.Point> {

  let smth = ed.utils.bytesToHex(base58.decode(pubScanStr));
  let pubScan =ed.Point.fromHex(bytesToHex(base58.decode(pubScanStr)));
  let pubSpend =ed.Point.fromHex(bytesToHex(base58.decode(pubspendstr)));

  let extendedEphem = await ed.utils.getExtendedPublicKey(base58.decode(ephemprivstr));

  let ephempriv = extendedEphem.scalar;

  let dest = await ed.utils.sha512(pubScan.multiply(ephempriv).toRawBytes());

  let a = await ed.utils.getExtendedPublicKey(dest.slice(0,32));

  return a.point.add(pubSpend);

}


/**
 * Generates scalar key for 
 *
 * @export
 * @param {string} privScanStr
 * @param {string} privSpendStr
 * @param {string} ephemStr
 * @return {*}  {Promise<string>}
 */
export async function receiverGenKey(privScanStr: string, privSpendStr: string, ephemStr: string): Promise<string> {


  let ephem = ed.Point.fromHex(ed.utils.bytesToHex(base58.decode(ephemStr)) );

  let privScan2 = new BN(base58.decode(privScanStr), 10, "le");
  let privScan = BigInt(privScan2.toString());
  let privSpend2 = new BN(base58.decode(privSpendStr), 10, "le");
  let privSpend = BigInt(privSpend2.toString());

  let dest = await ed.utils.sha512(ephem.multiply(privScan).toRawBytes());
  
  let expac = await ed.utils.getExtendedPublicKey(dest.slice(0,32))

  let res = expac.scalar + privSpend;
  
  res = ed.utils.mod(res, ed.CURVE.l);
  
let end = new BN(res.toString());
let reshex = res.toString(16);

if (reshex.length % 2) {
  reshex = '0' + reshex;
}


  return base58.encode(end.toBuffer("le"));
  
}
/**
 * Generates potential destination for a transaction 
 * Used to detect if transaction was sent towards an individual 
 *
 * @export
 * @param {string} privScanStr
 * @param {string} pubSpendStr
 * @param {string} ephemStr
 * @return {*}  {Promise<string>}
 */
export async function receiverGenDest(privScanStr: string, pubSpendStr: string, ephemStr: string): Promise<string> {


  let ephem = ed.Point.fromHex(ed.utils.bytesToHex(base58.decode(ephemStr)) );

  let privScan2 = new BN(base58.decode(privScanStr), 10, "le");
  let privScan = BigInt(privScan2.toString());
  let pubSpendPK = new PublicKey(base58.decode(pubSpendStr));
  let pubSpend = ed.Point.fromHex(bytesToHex(pubSpendPK.toBytes()));

  
  let dest = await ed.utils.sha512(ephem.multiply(privScan).toRawBytes());
  
  let expac = await ed.utils.getExtendedPublicKey(dest.slice(0,32))
  
  let res = expac.point.add(pubSpend);
  
  
  return base58.encode(res.toRawBytes());
  
}

/**
 * Generates scalar key from user signature of custom string
 *
 * @export
 * @param {Uint8Array} signature
 * @param {string} ephem
 * @return {*}  {Promise<string>}
 */
export async function receiverGenKeyWithSignature(signature:Uint8Array, ephem: string): Promise<string> {
  let hash = await ed.utils.sha512(signature);
  let privsc = await ed.utils.getExtendedPublicKey(hash.slice(0,32));
  let scan = new BN(privsc.scalar.toString(), 10, "le");
  let privsp = await ed.utils.getExtendedPublicKey(hash.slice(32,64));
  let spend = new BN(privsp.scalar.toString(), 10, "le");
  
  return receiverGenKey( base58.encode(ed.utils.hexToBytes(scan.toString("hex"))), base58.encode(ed.utils.hexToBytes(spend.toString("hex"))), ephem);

}


async function genSignature(m: Message, scalar: string, scalar2: string): Promise<Buffer>{
  let mes = m.serialize();

  let s2buff = base58.decode(scalar2);

  let sc = new BN(base58.decode(scalar), 10, "le");
  let s = BigInt(sc.toString());

  s = ed.utils.mod(s, ed.CURVE.l);
  let a = ed.Point.BASE.multiply(s);

  let unhashedR: Buffer = Buffer.concat([s2buff,mes]);
  let tempR: Uint8Array =  await ed.utils.sha512(unhashedR);

  let rc = new BN(tempR, 10, "le");
  let r = BigInt(rc.toString());

  r = ed.utils.mod(r, ed.CURVE.l);

  let pointr = ed.Point.BASE.multiply(r);

  let unhashedcombo = Buffer.concat([pointr.toRawBytes(), a.toRawBytes(), mes]);
  let tempcombo =await ed.utils.sha512(unhashedcombo);


  let comb = new BN(tempcombo, 58, "le");
  let combo = BigInt(comb.toString());


  combo = ed.utils.mod(combo, ed.CURVE.l);


  let bigs = combo * s + r;
  bigs = ed.utils.mod(bigs, ed.CURVE.l); 
  let bb = new BN(bigs.toString());


  let sig = Buffer.concat([pointr.toRawBytes(),bb.toBuffer("le")]);


  return sig;
   
}

/**
 * Generates a signature for a message given a stealth address' scalar key
 *
 * @export
 * @param {Message} m
 * @param {string} scalarkey
 * @return {*}  {Promise<Buffer>}
 */
export async function genFullSignature(m:Message, scalarkey: string) : Promise<Buffer>{
  let randNum = await genSignature(m,scalarkey,scalarkey);

  let x = randomBytesSeed(32, randNum);
  

  return genSignature(m, scalarkey, base58.encode(x));
}
/**
 * Signs a transaction given a stealth address' scalar key 
 *
 * @export
 * @param {Transaction} tx
 * @param {string} scalarKey
 * @return {*}  {Promise<Transaction>}
 */
export async function signTransaction(tx:Transaction, scalarKey: string ) :Promise<Transaction>{
  
  let sc = new BN(base58.decode(scalarKey), 10, "le"); //base doesn't matter
  let scalar = BigInt(sc.toString());

  let pubkey = ed.Point.BASE.multiply (scalar);
  
  
  let sig = await genFullSignature(tx.compileMessage(),scalarKey);
  tx.addSignature(new PublicKey(pubkey.toRawBytes()), sig);
  return tx;
}
/**
 * Create instruction to transfer to a stealth account
 *
 * @export
 * @param {PublicKey} source
 * @param {string} pubScan
 * @param {string} pubSpend
 * @param {number} amount
 * @return {*}  {Promise<TransactionInstruction>}
 */
export async function stealthTransferIx(source: PublicKey, pubScan : string, pubSpend: string, amount: number, ): Promise<TransactionInstruction>{
  
  let eph = ed.utils.randomPrivateKey();
  
  let dest = await senderGenAddress(pubScan,pubSpend, base58.encode(eph));
  let dksapmeta: AccountMeta = {pubkey:new PublicKey(dksap),
  isSigner: false,
  isWritable: false};
  let ephemmeta: AccountMeta = {pubkey: new PublicKey(await ed.getPublicKey(eph)),
  isSigner: false,
  isWritable: false};
  let tix = SystemProgram.transfer({
    fromPubkey: source,
    toPubkey: new PublicKey(dest.toRawBytes()),
    lamports: amount,
  });
   
  tix.keys.push(ephemmeta, dksapmeta);
  return tix;
}
/**
 * sends lamports to a recipient's stealth account
 *
 * @export
 * @param {Connection} connection
 * @param {Keypair} source 
 * @param {string} pubScan 
 * @param {string} pubSpend
 * @param {number} amount  amount in lamports to transfer 
 * @return {*}  {Promise<string>} returns result of send and confirm transaction
 */
export async function stealthTransfer(connection: Connection,source: Keypair, pubScan : string, pubSpend: string, amount: number ): Promise<string>{
  
  let tix = await stealthTransferIx(source.publicKey, pubScan, pubSpend, amount);
  let tx = new Transaction();
  tx.add(tix);

  let txid = await sendAndConfirmTransaction(connection, tx, [source]);
  return txid;
}
/**
 * Sends tokens to a stealth account
 *
 * @export
 * @param {Connection} connection
 * @param {Keypair} source not the token account
 * @param {PublicKey} token
 * @param {string} pubScan
 * @param {string} pubSpend
 * @param {number} amount
 * @return {*}  {Promise<string>}
 */
export async function stealthTokenTransfer(connection: Connection, source: Keypair, token: PublicKey, pubScan : string, pubSpend: string, amount: number ): Promise<string>{
  
  let eph = ed.utils.randomPrivateKey();
  

  let dest = await senderGenAddress(pubScan,pubSpend, base58.encode(eph));
  let destPub = new PublicKey(dest.toRawBytes());
  let dksapmeta: AccountMeta = {pubkey:new PublicKey(dksap),
  isSigner: false,
  isWritable: false};
  let ephemmeta: AccountMeta = {pubkey: new PublicKey(await ed.getPublicKey(eph)),
  isSigner: false,
  isWritable: false};
  let tokenMeta: AccountMeta = {pubkey: token,
    isSigner:false,
  isWritable: false};

  let tokenDest = await getAssociatedTokenAddress(token,destPub);
  let createix = createAssociatedTokenAccountInstruction(source.publicKey,tokenDest, destPub,token);

  let fromToken = await getAssociatedTokenAddress(token,source.publicKey);

  let tix = createTransferInstruction(fromToken, tokenDest, source.publicKey, amount);
  
   
  tix.keys.push(ephemmeta, tokenMeta, dksapmeta);

  let tx = new Transaction();
  tx.add(createix).add(tix);

  let txid = sendAndConfirmTransaction(connection, tx, [source]);

  return txid;
}

/**
 * Sends tokens to a recipient's stealth account
 *
 * @export
 * @param {Connection} connection
 * @param {Signer} payer
 * @param {PublicKey} source
 * @param {PublicKey} token not the associated token account (currently)
 * @param {string} pubScan
 * @param {string} pubSpend
 * @param {Signer} owner
 * @param {number} amount
 * @return {*}  {Promise<string>}
 */
export async function stealthTokenTransfer2(connection: Connection,payer: Signer, source: PublicKey, token: PublicKey, pubScan : string, pubSpend: string, owner: Signer, amount: number ): Promise<string>{
  
  let eph = ed.utils.randomPrivateKey();
  

  let dest = await senderGenAddress(pubScan,pubSpend, base58.encode(eph));
  let destPub = new PublicKey(dest.toRawBytes());
  let dksapmeta: AccountMeta = {pubkey:new PublicKey(dksap),
  isSigner: false,
  isWritable: false};
  let ephemmeta: AccountMeta = {pubkey: new PublicKey(await ed.getPublicKey(eph)),
  isSigner: false,
  isWritable: false};
  let tokenMeta: AccountMeta = {pubkey: token,
  isSigner:false,
isWritable: false};

  let tokenDest = await getAssociatedTokenAddress(token,destPub);
  let createix = createAssociatedTokenAccountInstruction(payer.publicKey,tokenDest, destPub,token);

  let fromToken = await getAssociatedTokenAddress(token,source);

  let tix = createTransferInstruction(fromToken, tokenDest, source, amount);
  
   
  tix.keys.push(ephemmeta, tokenMeta, dksapmeta);
  tix.keys

  let tx = new Transaction();
  tx.add(createix).add(tix);

  let txid = sendAndConfirmTransaction(connection, tx, [payer, owner]);

  return txid;
}

/**
 * Sends lamports from a stealth account given a scalar key
 * Note: sending directly to your main account is highly discouraged for security purposes
 *
 * @export
 * @param {Connection} connection
 * @param {string} key
 * @param {PublicKey} dest
 * @param {number} amount
 * @return {*}  {Promise<string>}
 */
export async function sendFromStealth(connection: Connection, key: string, dest: PublicKey, amount: number ): Promise<string> {
  let keyBN = new BN(base58.decode(key), 10, "le");
  let keyscalar = BigInt(keyBN.toString());
  let pub = ed.Point.BASE.multiply(keyscalar);
  let pk = new PublicKey(pub.toRawBytes());
  let tix = SystemProgram.transfer({
    fromPubkey: pk,
    toPubkey: dest,
    lamports: amount
  });

  tix.keys;
  let tx = new Transaction();
  tx.add(tix);
  tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
  tx.feePayer = pk;
  
  await signTransaction(tx, key);

  let txid = sendAndConfirmRawTransaction(connection,tx.serialize());
  return txid;
}

//note: this should not be used to transfer to your main account
//dest is the associated token account
// use signers?

/**
 * Sends tokens from a stealth account given a scalar key
 *
 * @export
 * @param {Connection} connection
 * @param {string} key
 * @param {PublicKey} token
 * @param {PublicKey} dest
 * @param {number} amount
 * @return {*}  {Promise<string>}
 */
export async function tokenFromStealth(connection: Connection, key: string, token: PublicKey, dest: PublicKey, amount: number): Promise<string> {
  let keyBN = new BN(base58.decode(key), 10, "le");
  let keyscalar = BigInt(keyBN.toString());
  
  let pub = ed.Point.BASE.multiply(keyscalar);
  let pk = new PublicKey(pub.toRawBytes());

  let fromToken = await getAssociatedTokenAddress(token,pk);
  let destToken = await getAssociatedTokenAddress(token,dest);

  let tix = createTransferInstruction(fromToken,destToken,pk,amount);

  let tx = new Transaction();
  tx.add(tix);
  tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
  tx.feePayer = pk;
  
  await signTransaction(tx, key);

  let txid = sendAndConfirmRawTransaction(connection,tx.serialize());
  return txid;
}


const fun = (value: PublicKey) => {
  return value.equals(new PublicKey(dksap));
}
/**
 * Class designed to store information when scanning for transactions
 * token will only be set if it is a token transfer
 *
 * @export
 * @class scanInfo
 */
export class scanInfo {
  account: string;
  ephem: string;
  token?: string;

  constructor(acct: string, eph: string, tok? : string){
    this.account = acct;
    this.ephem = eph;
    this.token = tok;
  }

}

/**
 * Checks whether a transaction was sent to the specific user
 *
 * @export
 * @param {Connection} connection
 * @param {string} sig
 * @param {string} privScanStr
 * @param {string} pubSpendStr
 * @return {*}  {Promise<scanInfo[]>}
 */
export async function scan_check(connection: Connection, sig: string,privScanStr : string, pubSpendStr: string ): Promise<scanInfo[]> {
  let accts: scanInfo[] = [];
  let tx = await connection.getTransaction(sig);
    if(!tx) return accts;

    let dks = new PublicKey(dksap);
    let mes  = tx.transaction.message;
    let pos = mes.accountKeys.findIndex(fun);
    
    for(let j = 0; j < mes.instructions.length; j++){
      let instr = mes.instructions[j];
      if (!instr.accounts.includes(pos)){
        continue;
      }

      //sol transaction
      //format is source, dest, ephem, dksap
      if(instr.accounts.length == 4){
        let ephem = mes.accountKeys[instr.accounts[2]];
        let dest = await receiverGenDest(privScanStr,pubSpendStr,ephem.toBase58());
        if (dest == mes.accountKeys[instr.accounts[1]].toBase58()){
          
          accts.push({account: dest, ephem: ephem.toBase58()});
        }
      } 

      //token transaction
      //format is source token account, dest, source,  ephem, token, dksap
      else if (instr.accounts.length == 6){
        let ephem = mes.accountKeys[instr.accounts[3]];
        let dest = await receiverGenDest(privScanStr,pubSpendStr,ephem.toBase58());
        let tokenDest = await getAssociatedTokenAddress(mes.accountKeys[instr.accounts[4]], new PublicKey (dest));
        if (tokenDest.toBase58() == mes.accountKeys[instr.accounts[1]].toBase58()){
          accts.push({account: dest, ephem: ephem.toBase58(), token: mes.accountKeys[instr.accounts[4]].toBase58()});
        }

      }
      
    }
    return accts;
} 
/**
 * Looks through previous transactions and returns those sent to a specific user
 * Note: this is not the optimal way, given that it only checks the last ___________________________________ß≈∂çƒ©∫˜˙∆µ
 *
 * @param {Connection} connection
 * @param {string} privScanStr
 * @param {string} pubSpendStr
 * @return {*}  {Promise<scanInfo[]>}
 */
async function scan(connection:Connection, privScanStr : string, pubSpendStr: string): Promise<scanInfo[]> {
  let accts: scanInfo[] = [];
  let res = await connection.getConfirmedSignaturesForAddress2(new PublicKey(dksap));
  for (let i = 0; i < res.length; i++){
    let sig = res[i];
    accts = accts.concat( await scan_check(connection, sig.signature, privScanStr, pubSpendStr));
    
  }
  return accts;
}