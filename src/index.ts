import {
    Connection,
    sendAndConfirmTransaction,
    Keypair,
    Transaction,
    SystemProgram,
    PublicKey,
    TransactionInstruction,
    Message,
    VersionedMessage,
    VersionedTransaction,
    MessageArgs,
    AccountMeta,
    sendAndConfirmRawTransaction,
    Signer,
    ConfirmedSignatureInfo,
  } from "@solana/web3.js";

  import {createAssociatedTokenAccountInstruction, getAssociatedTokenAddress, createTransferInstruction, transfer} from '@solana/spl-token'

import * as ed from '@noble/ed25519';
import * as base58 from 'bs58';
import { randomBytesSeed } from '@csquare/random-bytes-seed';
import { createPrinter, Signature } from "typescript";
import { BN } from "bn.js";
//import { dksap, pubsc, pubsp, privsc, privsp, bytes1 } from "./constants.js";


const bytes1 = new Uint8Array([54, 160, 60, 31, 94, 93, 163, 118, 126, 47, 127, //from
223, 96, 134, 231, 31, 171, 171, 98, 63, 245, 109,
164, 241, 196, 240, 233, 165, 195, 166, 66, 1, 

241,
51, 62, 197, 32, 71, 245, 174, 48, 162, 115, 166,
117, 169, 34, 2, 181, 90, 70, 72, 149, 88, 101,
171, 51, 40, 173, 124, 172, 117, 242, 121]);

const dksap = "3iUBKuvbRMPNLeF33QJHYia7ZBNDWqiccy35MXBRQd1f";
const pubsp = "AwpRFcxQN8XJscFrtgVbUu7k7AJAHDhHdQA85X6eWbvE";
const pubsc = "2Q9iYYe4osbQHh3jcL8Kp126iyznu1LAD6LR4N9h8gWQ";
const privsp = "BBC1qQ992HR4eVC4YtbJrCVxbsppmdhnzysCzmxG2TBh";
const privsc = "HzWVYni3BAdxjM3rMh9UDQajW2QjXJAtJc1ez8rxXYSA";
const privsp2 = "3Ev4d1S1qdGqDTwTqng81WNjPXNnDRFWijKRMQGsNxPb";
const privsc2 = "Dak3m7s2GcmRT26kwP1bnGkP1oGqNqVCBTVGeMVASeGW";
const ephem = "149a161f31779204faae57d0f73541abd21309783ebb73ecd67c189807403bbf";


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




//3yVqF5nKQQTTYrQFriftSPPq4gERPdSt3xQiq8ZMq3rY?


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



export async function receiverGenKey(privScanStr: string, privSpendStr: string, ephemStr: string): Promise<string> {

  console.log("genkey");

  let ephem = ed.Point.fromHex(ed.utils.bytesToHex(base58.decode(ephemStr)) );

  console.log(base58.encode(ephem.toRawBytes()));

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


  console.log("done");
  return base58.encode(end.toBuffer("le"));
  
}

async function receiverGenDest(privScanStr: string, pubSpendStr: string, ephemStr: string): Promise<string> {


  let ephem = ed.Point.fromHex(ed.utils.bytesToHex(base58.decode(ephemStr)) );

  let privScan2 = new BN(base58.decode(privScanStr), 10, "le");
  let privScan = BigInt(privScan2.toString());
  let pubSpendPK = new PublicKey(base58.decode(pubSpendStr));
  let pubSpend = ed.Point.fromHex(bytesToHex(pubSpendPK.toBytes()));

  //let privScan = extendedScan.scalar; 
  //let privSpend = extendedSpend.scalar;
  
  let dest = await ed.utils.sha512(ephem.multiply(privScan).toRawBytes());
  
  let expac = await ed.utils.getExtendedPublicKey(dest.slice(0,32))

  
  let res = expac.point.add(pubSpend);
  
  
  return base58.encode(res.toRawBytes());
  
}

//signature must be of custom message
async function receiverGenKeyWithSignature(signature:Uint8Array, ephem: string): Promise<string> {
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

async function genFullSignature(m:Message, scalar: string) : Promise<Buffer>{
  let randNum = await genSignature(m,scalar,scalar);

  let x = randomBytesSeed(32, randNum);
  

  return genSignature(m, scalar, base58.encode(x));
}

async function signTransaction(tx:Transaction, scalarKey: string ) :Promise<Transaction>{
  
  let sc = new BN(base58.decode(scalarKey), 10, "le"); //base doesn't matter
  let scalar = BigInt(sc.toString());

  let pubkey = ed.Point.BASE.multiply (scalar);
  
  
  let sig = await genFullSignature(tx.compileMessage(),scalarKey);
  tx.addSignature(new PublicKey(pubkey.toRawBytes()), sig);
  return tx;
}

async function stealthTransferIx(source: PublicKey, pubScan : string, pubSpend: string, amount: number, ): Promise<TransactionInstruction>{
  
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

async function stealthTransfer(connection: Connection,source: Keypair, pubScan : string, pubSpend: string, amount: number ): Promise<string>{
  
  let tix = await stealthTransferIx(source.publicKey, pubScan, pubSpend, amount);
  let tx = new Transaction();
  tx.add(tix);

  let txid = await sendAndConfirmTransaction(connection, tx, [source]);
  return txid;
}

async function stealthTokenTransfer(connection: Connection, source: Keypair, token: PublicKey, pubScan : string, pubSpend: string, amount: number ): Promise<string>{
  
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

//source is not the token account
async function stealthTokenTransfer2(connection: Connection,payer: Signer, source: PublicKey, token: PublicKey, pubScan : string, pubSpend: string, owner: Signer, amount: number ): Promise<string>{
  
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

//note: this should not be used to transfer to your main account
async function sendFromStealth(connection: Connection, key: string, dest: PublicKey, amount: number ): Promise<string> {
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
async function tokenFromStealth(connection: Connection, key: string, token: PublicKey, dest: PublicKey, amount: number): Promise<string> {
  let keyBN = new BN(base58.decode(key), 10, "le");
  let keyscalar = BigInt(keyBN.toString());
  //console.log(base58.encode(keyBN.toBuffer("le")));
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

class scanInfo {
  account: string;
  ephem: string;
  token?: string;

  constructor(acct: string, eph: string, tok? : string){
    this.account = acct;
    this.ephem = eph;
    this.token = tok;
  }

}

async function scan_check(connection: Connection, sig: string,privScanStr : string, pubSpendStr: string ): Promise<scanInfo[]> {
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
      
      //console.log(mes.instructions[j].accounts);
    }
    return accts;
} 

async function scan(connection:Connection, privScanStr : string, pubSpendStr: string): Promise<scanInfo[]> {
  let accts: scanInfo[] = [];
  let res = await connection.getConfirmedSignaturesForAddress2(new PublicKey(dksap));
  for (let i = 0; i < res.length; i++){
    //console.log("for loop"); 
    let sig = res[i];
    accts = accts.concat( await scan_check(connection, sig.signature, privScanStr, pubSpendStr));
    
  }
  return accts;
}