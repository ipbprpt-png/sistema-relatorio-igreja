const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_padrao_igreja';

app.use(cors());
app.use(express.json());

// Rota de Teste para checar se a API está no ar
app.get('/', (req, res) => {
  res.json({ mensagem: 'API do Relatório Anual da Igreja está funcionando perfeitamente!' });
});

// Middleware de Autenticação JWT
const autenticarToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ erro: 'Acesso negado. Token não fornecido.' });
  }

  jwt.verify(token, JWT_SECRET, (err, usuario) => {
    if (err) return res.status(403).json({ erro: 'Token inválido ou expirado.' });
    req.usuario = usuario;
    next();
  });
};

// 1. Rota de Cadastro de Igreja / Usuário
app.post('/api/auth/registrar', async (req, res) => {
  const { email, senha, nomeIgreja } = req.body;

  if (!email || !senha || !nomeIgreja) {
    return res.status(400).json({ erro: 'Preencha todos os campos obrigatórios.' });
  }

  try {
    const usuarioExiste = await prisma.usuario.findUnique({ where: { email } });
    if (usuarioExiste) {
      return res.status(400).json({ erro: 'E-mail já cadastrado.' });
    }

    const senhaHash = await bcrypt.hash(senha, 10);
    const novoUsuario = await prisma.usuario.create({
      data: {
        email,
        senha: senhaHash,
        nomeIgreja
      }
    });

    res.status(201).json({ mensagem: 'Igreja cadastrada com sucesso!' });
  } catch (err) {
    console.error('Erro no registro:', err);
    res.status(500).json({ erro: 'Erro ao cadastrar igreja no banco de dados.' });
  }
});

// 2. Rota de Login
app.post('/api/auth/login', async (req, res) => {
  const { email, senha } = req.body;

  try {
    const usuario = await prisma.usuario.findUnique({ where: { email } });
    if (!usuario) {
      return res.status(400).json({ erro: 'E-mail ou senha incorretos.' });
    }

    const senhaValida = await bcrypt.compare(senha, usuario.senha);
    if (!senhaValida) {
      return res.status(400).json({ erro: 'E-mail ou senha incorretos.' });
    }

    const token = jwt.sign(
      { id: usuario.id, email: usuario.email, nomeIgreja: usuario.nomeIgreja },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      token,
      nomeIgreja: usuario.nomeIgreja,
      mensagem: 'Login realizado com sucesso!'
    });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ erro: 'Erro ao realizar login.' });
  }
});

// 3. Rota para Salvar / Atualizar Relatório
app.post('/api/relatorio/salvar', autenticarToken, async (req, res) => {
  const { anoReferencia, estruturaDados, departamentos, rolMembros, financeiroPassado, financeiroFuturo, informacoesFinais } = req.body;
  const usuarioId = req.usuario.id;

  try {
    const relatorioExistente = await prisma.relatorio.findFirst({
      where: { usuarioId, anoReferencia: anoReferencia || 2026 }
    });

    if (relatorioExistente) {
      await prisma.relatorio.update({
        where: { id: relatorioExistente.id },
        data: {
          estruturaDados,
          departamentos,
          rolMembros,
          financeiroPassado,
          financeiroFuturo,
          informacoesFinais
        }
      });
      return res.json({ mensagem: 'Relatório atualizado com sucesso!' });
    } else {
      await prisma.relatorio.create({
        data: {
          usuarioId,
          anoReferencia: anoReferencia || 2026,
          estruturaDados,
          departamentos,
          rolMembros,
          financeiroPassado,
          financeiroFuturo,
          informacoesFinais
        }
      });
      return res.status(201).json({ mensagem: 'Relatório salvo com sucesso!' });
    }
  } catch (err) {
    console.error('Erro ao salvar relatório:', err);
    res.status(500).json({ erro: 'Erro ao salvar o relatório no banco de dados.' });
  }
});

// 4. Rota para Buscar o Relatório do Ano
app.get('/api/relatorio/:ano', autenticarToken, async (req, res) => {
  const ano = parseInt(req.params.ano) || 2026;
  const usuarioId = req.usuario.id;

  try {
    const relatorio = await prisma.relatorio.findFirst({
      where: { usuarioId, anoReferencia: ano }
    });

    if (!relatorio) {
      return res.status(404).json({ mensagem: 'Nenhum relatório encontrado para este ano.' });
    }

    res.json(relatorio);
  } catch (err) {
    console.error('Erro ao buscar relatório:', err);
    res.status(500).json({ erro: 'Erro ao buscar o relatório.' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});