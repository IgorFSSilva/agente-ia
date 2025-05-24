// index.js (backend atualizado com número de WhatsApp por agente)
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { OpenAI } = require('openai');

const app = express();
const port = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'chave-super-secreta';

app.use(cors());
app.options('*', cors());
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
  whatsappNumbers: [String], // Novo campo
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
  const { name, prompt, openaiToken, whatsappNumbers = [] } = req.body;
  const agent = await new Agent({ name, prompt, openaiToken, whatsappNumbers, userId: req.user.id }).save();
  res.status(201).json({ id: agent._id });
});

app.put('/api/agents/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { name, prompt, openaiToken, whatsappNumbers = [] } = req.body;

  const agent = await Agent.findOneAndUpdate(
    { _id: id, userId: req.user.id },
    { name, prompt, openaiToken, whatsappNumbers },
    { new: true }
  );

  if (!agent) return res.status(404).json({ error: 'Agente não encontrado' });

  res.json({ message: 'Agente atualizado com sucesso' });
});

app.get('/api/agents', authenticate, async (req, res) => {
  const agents = await Agent.find({ userId: req.user.id });
  res.json(agents);
});

app.get('/api/agents/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const agent = await Agent.findOne({ _id: id, userId: req.user.id });
  if (!agent) return res.status(404).json({ error: 'Agente não encontrado' });
  res.json(agent);
});

app.post('/api/agents/:id/query', authenticate, async (req, res) => {
  const { id } = req.params;
  const { question } = req.body;

  const agent = await Agent.findOne({ _id: id, userId: req.user.id });
  if (!agent) return res.status(404).json({ error: 'Agente não encontrado' });

  try {
    const openai = new OpenAI({ apiKey: agent.openaiToken });
    const chat = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        { role: 'system', content: agent.prompt },
        { role: 'user', content: question }
      ]
    });

    const answer = chat.choices[0].message.content;
    res.json({ answer });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao consultar a IA' });
  }
});

app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
