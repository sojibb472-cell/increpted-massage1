async function getKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"}, keyMaterial, {name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]);
}
async function encrypt() {
  const passwordEl=document.getElementById('password');
  const messageEl=document.getElementById('message');
  const outputEl=document.getElementById('output');
  const password=passwordEl.value;
  const text=messageEl.value;
  if(!password||!text) return alert("Password & message required");
  const enc=new TextEncoder();
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await getKey(password,salt);
  const encrypted=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,enc.encode(text));
  const combined=new Uint8Array([...salt,...iv,...new Uint8Array(encrypted)]);
  outputEl.value=btoa(String.fromCharCode(...combined));
  passwordEl.value='';messageEl.value='';
}
async function decrypt() {
  const passwordEl=document.getElementById('password');
  const messageEl=document.getElementById('message');
  const outputEl=document.getElementById('output');
  const password=passwordEl.value;
  const data=outputEl.value;
  if(!password||!data) return alert("Password & encrypted text required");
  try {
    const raw=Uint8Array.from(atob(data),c=>c.charCodeAt(0));
    const salt=raw.slice(0,16);
    const iv=raw.slice(16,28);
    const encrypted=raw.slice(28);
    const key=await getKey(password,salt);
    const decrypted=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,encrypted);
    messageEl.value=new TextDecoder().decode(decrypted);
    passwordEl.value='';
  } catch(e){alert("Wrong password or corrupted text!");}
}