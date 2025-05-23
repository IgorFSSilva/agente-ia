const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'chave-super-secreta';

// ✅ CORS configurado apenas para a URL do frontend no Vercel
const corsOptions = {
  origin: [
    'https://agente-ia-frontend.vercel.app',
    'https://agente-ia-frontend-seven.vercel.app'
  ],
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

app.options('*', cors(corsOptions));

app.use(bodyParser.json());

mongoose.connect(
  process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/agente-ia',
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    ssl: true,
    sslValidate: true
  }
);


const userSchema = new mongoose.Schema({
  email: String,
  passwordHash: String
});
const User = mongoose.model('User', userSchema);

const agentSchema = new mongoose.Schema({
  name: String,
  prompt: String,
  openaiToken: String,
  userId: mongoose.Schema.Types.ObjectId
});
const Agent = mongoose.model('Agent', agentSchema);

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token ausente' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
}

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (await User.findOne({ email }))
    return res.status(400).json({ error: 'E-mail já cadastrado' });
  const passwordHash = await bcrypt.hash(password, 10);
  await new User({ email, passwordHash }).save();
  res.status(201).json({ message: 'Usuário registrado com sucesso' });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: 'Credenciais inválidas' });
  const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET);
  res.json({ token });
});

app.post('/api/agents', authenticate, async (req, res) => {
  const { name, prompt, openaiToken } = req.body;
  const agent = await new Agent({ name, prompt, openaiToken, userId: req.user.id }).save();
  res.status(201).json({ id: agent._id });
});

app.get('/api/agents', authenticate, async (req, res) => {
  const agents = await Agent.find({ userId: req.user.id });
  res.json(agents);
});

app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
