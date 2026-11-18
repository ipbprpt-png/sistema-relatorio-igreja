require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_prpt_2026';

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ==================== MIDDLEWARES DE AUTENTICAÇÃO E PERFIL ====================
function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ erro: 'Token de acesso não fornecido.' });
  }

  jwt.verify(token, JWT_SECRET, (err, usuario) => {
    if (err) {
      return res.status(403).json({ erro: 'Token inválido ou expirado.' });
    }
    req.usuario = usuario;
    next();
  });
}

function exigirPerfil(...perfisPermitidos) {
  return (req, res, next) => {
    const roleUsuario = req.usuario.role || 'IGREJA';
    if (!perfisPermitidos.includes(roleUsuario)) {
      return res.status(403).json({ erro: 'Acesso negado para este tipo de perfil.' });
    }
    next();
  };
}

// ==================== ROTA DE SAÚDE ====================
app.get('/', (req, res) => {
  res.json({ status: 'API Presbitério de Ribeirão Preto (PRPT) online!' });
});

// ==================== AUTENTICAÇÃO (CADASTRO E LOGIN) ====================
app.post('/api/auth/cadastro', async (req, res) => {
  try {
    const { email, senha, nomeIgreja, role } = req.body;

    if (!email || !senha || !nomeIgreja) {
      return res.status(400).json({ erro: 'Preencha todos os campos obrigatórios.' });
    }

    // Permite apenas IGREJA ou MINISTRO no cadastro público (ADMIN é definido via banco/painel)
    const perfilValidado = role === 'MINISTRO' ? 'MINISTRO' : 'IGREJA';

    const usuarioExistente = await prisma.usuario.findUnique({ where: { email } });
    if (usuarioExistente) {
      return res.status(400).json({ erro: 'Este e-mail já está cadastrado.' });
    }

    const senhaHash = await bcrypt.hash(senha, 10);

    const novoUsuario = await prisma.usuario.create({
      data: {
        email,
        senha: senhaHash,
        nomeIgreja,
        role: perfilValidado
      }
    });

    res.status(201).json({
      mensagem: 'Conta criada com sucesso!',
      usuario: {
        id: novoUsuario.id,
        email: novoUsuario.email,
        nomeIgreja: novoUsuario.nomeIgreja,
        role: novoUsuario.role
      }
    });
  } catch (error) {
    console.error('Erro no cadastro:', error);
    res.status(500).json({ erro: 'Erro interno ao cadastrar conta.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body;

    const usuario = await prisma.usuario.findUnique({ where: { email } });
    if (!usuario) {
      return res.status(401).json({ erro: 'E-mail ou senha incorretos.' });
    }

    const senhaValida = await bcrypt.compare(senha, usuario.senha);
    if (!senhaValida) {
      return res.status(401).json({ erro: 'E-mail ou senha incorretos.' });
    }

    const roleAtual = usuario.role || 'IGREJA';

    const token = jwt.sign(
      {
        id: usuario.id,
        email: usuario.email,
        nomeIgreja: usuario.nomeIgreja,
        role: roleAtual
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      mensagem: 'Login realizado com sucesso!',
      token,
      nomeIgreja: usuario.nomeIgreja,
      role: roleAtual
    });
  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ erro: 'Erro interno ao realizar login.' });
  }
});

// ==================== RELATÓRIO 1: ESTATÍSTICO & FINANCEIRO (IGREJA / ADMIN) ====================
app.get('/api/relatorio/:ano', autenticarToken, exigirPerfil('IGREJA', 'ADMIN'), async (req, res) => {
  try {
    const ano = parseInt(req.params.ano) || 2026;
    const relatorio = await prisma.relatorio.findFirst({
      where: {
        usuarioId: req.usuario.id,
        anoReferencia: ano
      },
      orderBy: { atualizadoEm: 'desc' }
    });

    if (!relatorio) {
      return res.status(404).json({ mensagem: 'Nenhum relatório encontrado para este ano.' });
    }

    res.json(relatorio);
  } catch (error) {
    console.error('Erro ao buscar relatório:', error);
    res.status(500).json({ erro: 'Erro interno ao carregar relatório.' });
  }
});

app.post('/api/relatorio/salvar', autenticarToken, exigirPerfil('IGREJA', 'ADMIN'), async (req, res) => {
  try {
    const {
      anoReferencia,
      estruturaDados,
      departamentos,
      rolMembros,
      financeiroPassado,
      financeiroFuturo,
      informacoesFinais
    } = req.body;

    const ano = parseInt(anoReferencia) || 2026;

    const existente = await prisma.relatorio.findFirst({
      where: { usuarioId: req.usuario.id, anoReferencia: ano }
    });

    let relatorioSalvo;
    if (existente) {
      relatorioSalvo = await prisma.relatorio.update({
        where: { id: existente.id },
        data: {
          estruturaDados,
          departamentos,
          rolMembros,
          financeiroPassado,
          financeiroFuturo,
          informacoesFinais
        }
      });
    } else {
      relatorioSalvo = await prisma.relatorio.create({
        data: {
          usuarioId: req.usuario.id,
          anoReferencia: ano,
          estruturaDados,
          departamentos,
          rolMembros,
          financeiroPassado,
          financeiroFuturo,
          informacoesFinais
        }
      });
    }

    res.json({ mensagem: 'Relatório Estatístico salvo com sucesso!', relatorio: relatorioSalvo });
  } catch (error) {
    console.error('Erro ao salvar relatório:', error);
    res.status(500).json({ erro: 'Erro interno ao salvar relatório.' });
  }
});

// ==================== RELATÓRIO 2: CONSELHO / MESA (IGREJA / ADMIN) ====================
app.get('/api/relatorio-conselho/:ano', autenticarToken, exigirPerfil('IGREJA', 'ADMIN'), async (req, res) => {
  try {
    const ano = parseInt(req.params.ano) || 2026;
    const relatorio = await prisma.relatorioConselho.findUnique({
      where: {
        usuarioId_anoReferencia: {
          usuarioId: req.usuario.id,
          anoReferencia: ano
        }
      }
    });

    if (!relatorio) {
      return res.status(404).json({ mensagem: 'Nenhum relatório do Conselho encontrado para este ano.' });
    }

    res.json(relatorio);
  } catch (error) {
    console.error('Erro ao buscar relatório do Conselho:', error);
    res.status(500).json({ erro: 'Erro interno ao carregar relatório do Conselho.' });
  }
});

app.post('/api/relatorio-conselho/salvar', autenticarToken, exigirPerfil('IGREJA', 'ADMIN'), async (req, res) => {
  try {
    const {
      anoReferencia,
      identificacao,
      organizacao,
      supervisaoEspiritual,
      supervisaoAdmin,
      planejamentoPatrimonio,
      informacoesFinais
    } = req.body;

    const ano = parseInt(anoReferencia) || 2026;

    const relatorioSalvo = await prisma.relatorioConselho.upsert({
      where: {
        usuarioId_anoReferencia: {
          usuarioId: req.usuario.id,
          anoReferencia: ano
        }
      },
      update: {
        identificacao,
        organizacao,
        supervisaoEspiritual,
        supervisaoAdmin,
        planejamentoPatrimonio,
        informacoesFinais
      },
      create: {
        usuarioId: req.usuario.id,
        anoReferencia: ano,
        identificacao,
        organizacao,
        supervisaoEspiritual,
        supervisaoAdmin,
        planejamentoPatrimonio,
        informacoesFinais
      }
    });

    res.json({ mensagem: 'Relatório do Conselho salvo com sucesso!', relatorio: relatorioSalvo });
  } catch (error) {
    console.error('Erro ao salvar relatório do Conselho:', error);
    res.status(500).json({ erro: 'Erro interno ao salvar relatório do Conselho.' });
  }
});

// ==================== RELATÓRIO 3: MINISTRO PRESBITERIANO (MINISTRO / ADMIN) ====================
app.get('/api/relatorio-ministro/:ano', autenticarToken, exigirPerfil('MINISTRO', 'ADMIN'), async (req, res) => {
  try {
    const ano = parseInt(req.params.ano) || 2026;
    const relatorios = await prisma.relatorioMinistro.findMany({
      where: {
        usuarioId: req.usuario.id,
        anoReferencia: ano
      },
      orderBy: { atualizadoEm: 'desc' }
    });

    res.json(relatorios);
  } catch (error) {
    console.error('Erro ao listar relatórios de ministros:', error);
    res.status(500).json({ erro: 'Erro interno ao carregar relatórios de ministros.' });
  }
});

app.post('/api/relatorio-ministro/salvar', autenticarToken, exigirPerfil('MINISTRO', 'ADMIN'), async (req, res) => {
  try {
    const {
      id,
      anoReferencia,
      nomeMinistro,
      identificacaoCampo,
      liderancaPastoral,
      nutricaoEspiritual,
      assistenciaPastoral,
      protecaoPastoral,
      outrasInformacoes
    } = req.body;

    if (!nomeMinistro || !nomeMinistro.trim()) {
      return res.status(400).json({ erro: 'O nome do ministro é obrigatório.' });
    }

    const ano = parseInt(anoReferencia) || 2026;
    let relatorioSalvo;

    if (id) {
      const existente = await prisma.relatorioMinistro.findFirst({
        where: { id, usuarioId: req.usuario.id }
      });

      if (!existente) {
        return res.status(404).json({ erro: 'Relatório do ministro não encontrado.' });
      }

      relatorioSalvo = await prisma.relatorioMinistro.update({
        where: { id },
        data: {
          anoReferencia: ano,
          nomeMinistro: nomeMinistro.trim(),
          identificacaoCampo,
          liderancaPastoral,
          nutricaoEspiritual,
          assistenciaPastoral,
          protecaoPastoral,
          outrasInformacoes
        }
      });
    } else {
      relatorioSalvo = await prisma.relatorioMinistro.create({
        data: {
          usuarioId: req.usuario.id,
          anoReferencia: ano,
          nomeMinistro: nomeMinistro.trim(),
          identificacaoCampo,
          liderancaPastoral,
          nutricaoEspiritual,
          assistenciaPastoral,
          protecaoPastoral,
          outrasInformacoes
        }
      });
    }

    res.json({
      mensagem: 'Relatório do Ministro salvo com sucesso!',
      id: relatorioSalvo.id,
      relatorio: relatorioSalvo
    });
  } catch (error) {
    console.error('Erro ao salvar relatório do ministro:', error);
    res.status(500).json({ erro: 'Erro interno ao salvar relatório do ministro.' });
  }
});

// ==================== ROTAS ADMINISTRATIVAS (SECRETARIA PRPT / ADMIN) ====================
app.get('/api/admin/painel/:ano', autenticarToken, exigirPerfil('ADMIN'), async (req, res) => {
  try {
    const ano = parseInt(req.params.ano) || 2026;

    const usuarios = await prisma.usuario.findMany({
      orderBy: { nomeIgreja: 'asc' },
      select: {
        id: true,
        email: true,
        nomeIgreja: true,
        role: true,
        criadoEm: true,
        relatorios: {
          where: { anoReferencia: ano },
          orderBy: { atualizadoEm: 'desc' }
        },
        relatoriosConselho: {
          where: { anoReferencia: ano },
          orderBy: { atualizadoEm: 'desc' }
        },
        relatoriosMinistro: {
          where: { anoReferencia: ano },
          orderBy: { atualizadoEm: 'desc' }
        }
      }
    });

    const igrejas = usuarios.filter(u => u.role === 'IGREJA');
    const ministros = usuarios.filter(u => u.role === 'MINISTRO');

    const resumo = {
      totalIgrejas: igrejas.length,
      igrejasComEstatistico: igrejas.filter(i => i.relatorios.length > 0).length,
      igrejasComConselho: igrejas.filter(i => i.relatoriosConselho.length > 0).length,
      totalMinistrosCadastrados: ministros.length,
      totalRelatoriosMinistros: usuarios.reduce((acc, u) => acc + u.relatoriosMinistro.length, 0)
    };

    res.json({ ano, resumo, usuarios });
  } catch (error) {
    console.error('Erro no painel admin:', error);
    res.status(500).json({ erro: 'Erro ao carregar dados administrativos.' });
  }
});

// Permite ao Admin criar nova conta (Igreja, Ministro ou Admin) diretamente pelo painel
app.post('/api/admin/usuarios', autenticarToken, exigirPerfil('ADMIN'), async (req, res) => {
  try {
    const { email, senha, nomeIgreja, role } = req.body;

    if (!email || !senha || !nomeIgreja || !role) {
      return res.status(400).json({ erro: 'Preencha todos os campos obrigatórios.' });
    }

    if (!['IGREJA', 'MINISTRO', 'ADMIN'].includes(role)) {
      return res.status(400).json({ erro: 'Perfil inválido.' });
    }

    const existente = await prisma.usuario.findUnique({ where: { email } });
    if (existente) {
      return res.status(400).json({ erro: 'Este e-mail já está cadastrado.' });
    }

    const senhaHash = await bcrypt.hash(senha, 10);

    const novo = await prisma.usuario.create({
      data: {
        email,
        senha: senhaHash,
        nomeIgreja,
        role
      },
      select: { id: true, email: true, nomeIgreja: true, role: true, criadoEm: true }
    });

    res.status(201).json({ mensagem: 'Conta criada com sucesso!', usuario: novo });
  } catch (error) {
    console.error('Erro ao criar usuário (Admin):', error);
    res.status(500).json({ erro: 'Erro interno ao criar conta.' });
  }
});

// Permite ao Admin alterar o perfil de um usuário
app.patch('/api/admin/usuario/:id/role', autenticarToken, exigirPerfil('ADMIN'), async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    if (!['IGREJA', 'MINISTRO', 'ADMIN'].includes(role)) {
      return res.status(400).json({ erro: 'Perfil inválido.' });
    }

    const atualizado = await prisma.usuario.update({
      where: { id },
      data: { role },
      select: { id: true, email: true, nomeIgreja: true, role: true }
    });

    res.json({ mensagem: 'Perfil atualizado com sucesso!', usuario: atualizado });
  } catch (error) {
    console.error('Erro ao atualizar perfil:', error);
    res.status(500).json({ erro: 'Erro ao atualizar perfil do usuário.' });
  }
});

// Permite ao Admin excluir um usuário
app.delete('/api/admin/usuario/:id', autenticarToken, exigirPerfil('ADMIN'), async (req, res) => {
  try {
    const { id } = req.params;

    if (id === req.usuario.id) {
      return res.status(400).json({ erro: 'Você não pode excluir sua própria conta de administrador.' });
    }

    await prisma.usuario.delete({ where: { id } });
    res.json({ mensagem: 'Usuário excluído com sucesso.' });
  } catch (error) {
    console.error('Erro ao excluir usuário:', error);
    res.status(500).json({ erro: 'Erro ao excluir usuário. Verifique se há registros vinculados.' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor PRPT rodando na porta ${PORT}`);
});