const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database("digistore.db");
const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadDir, {recursive:true});

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret-in-production",
  resave:false, saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:"lax",secure:false,maxAge:1000*60*60*24*7}
}));
app.use(express.static(path.join(__dirname,"public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL, description TEXT DEFAULT '',
 category TEXT NOT NULL, price_cents INTEGER NOT NULL,
 file_name TEXT NOT NULL, original_name TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL, total_cents INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 payment_reference TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS order_items(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 order_id INTEGER NOT NULL, product_id INTEGER NOT NULL,
 price_cents INTEGER NOT NULL,
 FOREIGN KEY(order_id) REFERENCES orders(id),
 FOREIGN KEY(product_id) REFERENCES products(id)
);
`);

const adminEmail = process.env.ADMIN_EMAIL || "admin@digistore.local";
const adminPassword = process.env.ADMIN_PASSWORD || "ChangeMe123!";
if (!db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail)) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')")
    .run("Prisca Lonyama Kumuna", adminEmail, hash);
}

const storage = multer.diskStorage({
 destination: (_,__,cb)=>cb(null,uploadDir),
 filename: (_,file,cb)=>cb(null,Date.now()+"-"+Math.random().toString(36).slice(2)+"-"+file.originalname.replace(/[^a-zA-Z0-9._-]/g,"_"))
});
const upload = multer({storage, limits:{fileSize:500*1024*1024}});

function auth(req,res,next){ if(!req.session.user) return res.status(401).json({error:"Connexion requise"}); next(); }
function admin(req,res,next){ if(!req.session.user || req.session.user.role!=="admin") return res.status(403).json({error:"Accès administrateur requis"}); next(); }

app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));

app.post("/api/register", async (req,res)=>{
  const {name,email,password}=req.body;
  if(!name||!email||!password||password.length<8) return res.status(400).json({error:"Nom, email et mot de passe (8 caractères minimum) requis."});
  try{
    const hash=await bcrypt.hash(password,12);
    const r=db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name,email.toLowerCase(),hash);
    req.session.user={id:r.lastInsertRowid,name,email:email.toLowerCase(),role:"customer"};
    res.json({ok:true,user:req.session.user});
  }catch(e){res.status(400).json({error:"Cet email est déjà utilisé."});}
});

app.post("/api/login", async (req,res)=>{
  const {email,password}=req.body;
  const u=db.prepare("SELECT * FROM users WHERE email=?").get((email||"").toLowerCase());
  if(!u || !(await bcrypt.compare(password||"",u.password_hash))) return res.status(401).json({error:"Identifiants incorrects."});
  req.session.user={id:u.id,name:u.name,email:u.email,role:u.role};
  res.json({ok:true,user:req.session.user});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/products",(req,res)=>{
  const rows=db.prepare("SELECT id,name,description,category,price_cents,original_name,created_at FROM products ORDER BY id DESC").all();
  res.json(rows);
});

app.post("/api/products",admin,upload.single("file"),(req,res)=>{
  if(!req.file) return res.status(400).json({error:"Fichier requis."});
  const {name,description="",category="Autre",price}=req.body;
  const priceCents=Math.round(Number(price)*100);
  if(!name || !Number.isFinite(priceCents) || priceCents<0) return res.status(400).json({error:"Nom et prix valides requis."});
  const r=db.prepare(`INSERT INTO products(name,description,category,price_cents,file_name,original_name) VALUES(?,?,?,?,?,?)`)
    .run(name,description,category,priceCents,req.file.filename,req.file.originalname);
  res.json({ok:true,id:r.lastInsertRowid});
});

app.delete("/api/products/:id",admin,(req,res)=>{
  const p=db.prepare("SELECT file_name FROM products WHERE id=?").get(req.params.id);
  if(!p) return res.status(404).json({error:"Produit introuvable"});
  db.prepare("DELETE FROM products WHERE id=?").run(req.params.id);
  try{fs.unlinkSync(path.join(uploadDir,p.file_name))}catch{}
  res.json({ok:true});
});

app.post("/api/orders",auth,(req,res)=>{
  const ids=[...new Set((req.body.productIds||[]).map(Number).filter(Boolean))];
  if(!ids.length) return res.status(400).json({error:"Panier vide"});
  const products=db.prepare(`SELECT * FROM products WHERE id IN (${ids.map(()=>"?").join(",")})`).all(...ids);
  if(products.length!==ids.length) return res.status(400).json({error:"Produit introuvable"});
  const total=products.reduce((s,p)=>s+p.price_cents,0);
  const create=db.transaction(()=>{
    const order=db.prepare("INSERT INTO orders(user_id,total_cents,status) VALUES(?,?,?)").run(req.session.user.id,total,"pending");
    const ins=db.prepare("INSERT INTO order_items(order_id,product_id,price_cents) VALUES(?,?,?)");
    for(const p of products) ins.run(order.lastInsertRowid,p.id,p.price_cents);
    return order.lastInsertRowid;
  });
  const id=create();
  res.json({ok:true,orderId:id,totalCents:total,status:"pending",
    message:"Commande créée. Branche ici le prestataire de paiement pour confirmer automatiquement le paiement."});
});

app.get("/api/my-orders",auth,(req,res)=>{
  const orders=db.prepare("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC").all(req.session.user.id);
  for(const o of orders) o.items=db.prepare(`SELECT oi.*,p.name,p.original_name FROM order_items oi JOIN products p ON p.id=oi.product_id WHERE oi.order_id=?`).all(o.id);
  res.json(orders);
});

/* Démo locale: l'admin peut marquer une commande comme payée.
   En production, cette action doit être remplacée par un webhook signé
   du prestataire de paiement. */
app.post("/api/orders/:id/mark-paid",admin,(req,res)=>{
  db.prepare("UPDATE orders SET status='paid',payment_reference=? WHERE id=?")
    .run(req.body.reference||"MANUAL",req.params.id);
  res.json({ok:true});
});

app.get("/api/download/:orderId/:productId",auth,(req,res)=>{
  const row=db.prepare(`
    SELECT o.status,p.file_name,p.original_name FROM orders o
    JOIN order_items oi ON oi.order_id=o.id
    JOIN products p ON p.id=oi.product_id
    WHERE o.id=? AND o.user_id=? AND p.id=?`).get(req.params.orderId,req.session.user.id,req.params.productId);
  if(!row) return res.status(404).send("Fichier introuvable");
  if(row.status!=="paid") return res.status(402).send("Paiement non confirmé");
  res.download(path.join(uploadDir,row.file_name),row.original_name);
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`DigiStore by PKL: http://localhost:${PORT}`));
