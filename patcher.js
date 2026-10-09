// Browser-compatible patcher for ACNH 3.0.3. No networking or uploads.
(function(root){
'use strict';
const OFFSET=0xB84240,SIZE=0x754,HASH_START=0x104,HASH_END=0xB8A4E0;
const u32=(v)=>v>>>0;
function mixHash(bytes){
 let h=0, n=bytes.length>>>2, i=0;
 for(let t=0;t<n;t++,i+=4){
  let k=u32(bytes[i]|bytes[i+1]<<8|bytes[i+2]<<16|bytes[i+3]<<24);
  k=Math.imul(k,0xcc9e2d51); k=u32(k<<15|k>>>17); k=Math.imul(k,0x1b873593);
  h^=k;h=u32(h<<13|h>>>19);h=u32(Math.imul(h,5)+0xe6546b64);
 }
 let k=0;for(let j=0;i<bytes.length;i++,j++)k|=bytes[i]<<(8*j);
 if(bytes.length&3){k=Math.imul(k,0xcc9e2d51);k=u32(k<<15|k>>>17);k=Math.imul(k,0x1b873593);h^=k;}
 h^=bytes.length;h^=h>>>16;h=Math.imul(h,0x85ebca6b);h^=h>>>13;h=Math.imul(h,0xc2b2ae35);h^=h>>>16;
 return u32(h);
}
class SeadRandom {
 constructor(seed){this.s=[];for(let i=0;i<4;i++){
 let p=i===0?seed:this.s[i-1];this.s.push(u32(Math.imul(p^(p>>>30),0x6c078965)+i+1));
 }}
 u32(){let a=u32(this.s[0] ^ (this.s[0]<<11));
  this.s[0]=this.s[1];this.s[1]=this.s[2];this.s[2]=this.s[3];
  this.s[3]=u32(a ^ (a>>>8) ^ this.s[3] ^ (this.s[3]>>>19));return this.s[3];}
 u64(){let a=u32(this.s[0]^(this.s[0]<<11)),b=this.s[1],c=this.s[3];
  this.s[0]=this.s[2];this.s[1]=c;
  b=u32(b^(b<<11));a=u32(a^(a>>>8)^c);c=u32(a^(c>>>19));
  a=u32(b^(b>>>8)^c^(a>>>19));this.s[2]=c;this.s[3]=a;
 }
}
function aesParams(header){
 if(header.length<0x300)throw Error('Missing or invalid wherearenHeader.dat');
 const dv=new DataView(header.buffer,header.byteOffset,header.byteLength);
 const block=Array.from({length:128},(_,i)=>dv.getUint32(0x100+i*4,true));
 function generate(pos){
  let r=new SeadRandom(block[block[pos]&0x7f]);
  const skip=(block[block[pos+1]&0x7f]&15)+1;
  for(let i=0;i<skip;i++)r.u64();
  return Uint8Array.from({length:16},()=>r.u32()>>>24);
 }
 return [generate(0),generate(2)];
}
async function crypt(data,header){
 const [keyBytes,counter]=aesParams(header);
 const key=await crypto.subtle.importKey('raw',keyBytes,{name:'AES-CTR'},false,['encrypt']);
 return new Uint8Array(await crypto.subtle.encrypt({name:'AES-CTR',counter,length:128},key,data));
}
function check(raw){
 if(raw.length<HASH_END)throw Error('Unsupported save: wherearen.dat is too short');
 const dv=new DataView(raw.buffer,raw.byteOffset,raw.byteLength);
 if(dv.getUint32(0x100,true)!==mixHash(raw.subarray(HASH_START,HASH_END)))throw Error('Save checksum mismatch or unsupported version');
}
async function patchZip(data,mask,progress=()=>{}){
 if(mask.length!==SIZE)throw Error('Invalid furniture mask');
 const zip=await root.JSZip.loadAsync(data,{checkCRC32:true});
 const targets=Object.keys(zip.files).filter(n=>/^(.+\/)?Villager[^/]+\/wherearen\.dat$/.test(n));
 if(targets.length!==1)throw Error('Expected one Villager*/wherearen.dat');
 const name=targets[0],headerName=name.replace(/wherearen\.dat$/,'wherearenHeader.dat');
 if(!zip.file(headerName))throw Error('Missing wherearenHeader.dat');
 const [enc,header]=await Promise.all([zip.file(name).async('uint8array'),zip.file(headerName).async('uint8array')]);
 progress('Decrypting save…');
 const raw=await crypt(enc,header); check(raw);
 let changed=0,added=0;
 for(let i=0;i<SIZE;i++){
  const pos=OFFSET+i,old=raw[pos],newval=old|mask[i];
  if(old!==newval){raw[pos]=newval;changed++;let n=newval^old;while(n){n&=n-1;added++;}}
 }
 new DataView(raw.buffer,raw.byteOffset,raw.byteLength).setUint32(0x100,mixHash(raw.subarray(HASH_START,HASH_END)),true);
 progress('Re-encrypting save…');
 const result=await crypt(raw,header);
 zip.file(name,result,{binary:true,date:zip.file(name).date});
 progress('Writing ZIP…');
 const out=await zip.generateAsync({type:'uint8array',compression:'DEFLATE',compressionOptions:{level:6}});
 return {zip:out,changed,added};
}
root.ParadiseUnlocked={patchZip,crypt,mixHash,aesParams};
})(typeof globalThis==='object'?globalThis:this);
