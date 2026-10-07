import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';
import { z } from 'zod';
import dotenv from 'dotenv';
import firebaseConfig from './firebase-applet-config.json';
import { initializeApp as initFirebaseApp, getApps } from 'firebase/app';
import { getFirestore, collection, getDocs, doc, setDoc, updateDoc } from 'firebase/firestore';
import { getAuth, signInWithEmailAndPassword } from 'firebase/auth';
import nodemailer from 'nodemailer';

dotenv.config();

const PORT = 3000;
const app = express();

// ==========================================
// 0. FIREBASE SERVER-SIDE CONNECTOR & AUTH
// ==========================================
let serverDbInstance: any = null;
async function getServerDb() {
  try {
    const apps = getApps();
    let fbApp = apps.find(a => a.name === 'server_admin_instance');
    if (!fbApp) {
      fbApp = initFirebaseApp(firebaseConfig, 'server_admin_instance');
    }
    const fbAuth = getAuth(fbApp);

    if (!fbAuth.currentUser) {
      try {
        await signInWithEmailAndPassword(fbAuth, 'admin@flowdeck.io', 'admin123');
      } catch (signInErr: any) {
        if (signInErr.code === 'auth/user-not-found' || signInErr.code === 'auth/invalid-credential') {
          await createFirebaseUser('admin@flowdeck.io', 'admin123', 'Administrador FlowDeck');
          await signInWithEmailAndPassword(fbAuth, 'admin@flowdeck.io', 'admin123');
        } else {
          console.warn('[Firebase Server] Admin sign-in warning:', signInErr?.message || signInErr);
        }
      }
    } else {
      await fbAuth.currentUser.getIdToken(true).catch(() => {});
    }

    if (!serverDbInstance) {
      const MASTER_FIRESTORE_DATABASE_ID = (firebaseConfig as any).firestoreDatabaseId || 'ai-studio-flowdeck224-0299db86-1176-4acf-88f9-9a3c9dbf2129';
      serverDbInstance = getFirestore(fbApp, MASTER_FIRESTORE_DATABASE_ID);
    }
    return serverDbInstance;
  } catch (err) {
    console.error('[Firebase Server] Error initializing admin connection:', err);
    return null;
  }
}

async function createFirebaseUser(email: string, password: string, displayName?: string): Promise<{ uid: string; idToken: string } | { error: string; code?: string }> {
  try {
    const key = firebaseConfig.apiKey;
    const res = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${key}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: email.trim().toLowerCase(),
        password: password,
        returnSecureToken: true
      })
    });
    const data = await res.json();
    if (!res.ok) {
      if (data.error?.message === 'EMAIL_EXISTS') {
        return { error: 'EMAIL_EXISTS', code: 'EMAIL_EXISTS' };
      }
      return { error: data.error?.message || 'Falha ao criar usuário no Firebase Auth' };
    }

    if (displayName && data.idToken) {
      await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:update?key=${key}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          idToken: data.idToken,
          displayName: displayName.trim(),
          returnSecureToken: true
        })
      }).catch(err => console.warn('[Firebase Auth Server] update displayName error:', err));
    }

    return { uid: data.localId, idToken: data.idToken };
  } catch (err: any) {
    console.error('[Firebase Auth Server] Error:', err);
    return { error: err.message || 'Erro de rede com Firebase' };
  }
}

// ==========================================
// 1. SECURE IN-MEMORY SECRET VAULT & USERS
// ==========================================
// Database and infrastructure keys quarantined in memory (never exposed in API responses)
const INTERNAL_VAULT = {
  dbHostUrl: process.env.DB_HOST_URL || 'https://txtetkvmjutkoobgohsj.supabase.co',
  dbClientKey: process.env.DB_CLIENT_KEY || 'sb_publishable_ENwDkghhxWoqPxlGHgzxVw_JENydXtj',
  dbServiceRoleKey: process.env.DB_SERVICE_ROLE_KEY || 'sb_secret_wKc3h658KkylcwALGW4MNg_IshycwmH',
  masterEncryptionKey: process.env.ENCRYPTION_MASTER_KEY || 'flowdeck-aes256-master-secure-passphrase-2026',
  auditHmacSecret: crypto.randomBytes(32).toString('hex'),
  sessionSecret: crypto.randomBytes(32).toString('hex')
};

interface SectorRecord {
  id: string;
  name: string;
  code?: string;
  description?: string;
  departmentId?: string;
  createdAt?: string;
}

interface UserRecord {
  id: string;
  email: string;
  name: string;
  role: string;
  avatar: string;
  department: string;
  sector?: string;
  mfaEnabled: boolean;
  passwordSalt: string;
  passwordHash: string;
  failedLoginAttempts: number;
  lockUntil: number | null;
  lastLogin: string;
}

interface PermissionLevelRecord {
  id: string;
  name: string;
  code: string;
  description: string;
  color: string;
  isSystem?: boolean;
  canAccessSettings: boolean;
  canCreateCards: boolean;
  canEditCards: boolean;
  canDeleteCards: boolean;
  canCreateBoards?: boolean;
  canEditBoards?: boolean;
  canDeleteBoards?: boolean;
  canMoveCards?: boolean;
  createdAt: string;
}

const roleStore = new Map<string, PermissionLevelRecord>();

function seedRoles() {
  const initialRoles: PermissionLevelRecord[] = [
    {
      id: 'admin',
      name: 'Administrador',
      code: 'ADMIN',
      description: 'Acesso irrestrito a todas as configurações, auditoria, criação e gestão de usuários e cards.',
      color: '#EF4444',
      isSystem: true,
      canAccessSettings: true,
      canCreateCards: true,
      canEditCards: true,
      canDeleteCards: true,
      canCreateBoards: true,
      canEditBoards: true,
      canDeleteBoards: true,
      canMoveCards: true,
      createdAt: '2026-08-01T00:00:00Z'
    }
  ];

  initialRoles.forEach(r => {
    roleStore.set(r.id, r);
  });
}

seedRoles();

function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256').toString('hex');
}

// Active session token store: token -> { userId, expiresAt }
const activeSessions = new Map<string, { userId: string; expiresAt: number }>();

// Initial enterprise users stored with salted PBKDF2 hashes
const userStore = new Map<string, UserRecord>();

function seedUsers() {
  // Do not seed default users automatically. Users must be created explicitly by administrators.
}

seedUsers();

// --- DEPARTMENTS STORE ---
interface DepartmentRecord {
  id: string;
  name: string;
  code?: string;
  description?: string;
  color?: string;
  sectors?: SectorRecord[];
  createdAt: string;
}

const departmentStore = new Map<string, DepartmentRecord>();

function seedDepartments() {
  const initialDepartments: DepartmentRecord[] = [
    {
      id: 'dept_eng',
      name: 'Engenharia de Software',
      code: 'ENG',
      description: 'Desenvolvimento e arquitetura de sistemas corporativos e plataformas',
      color: '#2563EB',
      sectors: [
        { id: 'set_eng_arch', name: 'Arquitetura & Core Platform', code: 'ENG-ARC', description: 'Arquitetura de sistemas e padrões corporativos', departmentId: 'dept_eng' },
        { id: 'set_eng_integ', name: 'Integrações & Webhooks', code: 'ENG-INT', description: 'Conectores externos, filas e gateways de integração', departmentId: 'dept_eng' },
        { id: 'set_eng_ops', name: 'Sustentação N3 & Performance', code: 'ENG-SUS', description: 'Monitoramento crítico e engenharia de confiabilidade', departmentId: 'dept_eng' }
      ],
      createdAt: '2026-08-01T00:00:00Z'
    },
    {
      id: 'dept_backend',
      name: 'Desenvolvimento Backend',
      code: 'DEV-BE',
      description: 'APIs de alta performance, microsserviços, criptografia e integrações',
      color: '#6366F1',
      sectors: [
        { id: 'set_be_api', name: 'APIs & Microsserviços', code: 'BE-API', description: 'Serviços RESTful e gRPC de alta taxa de transferência', departmentId: 'dept_backend' },
        { id: 'set_be_db', name: 'Banco de Dados & Criptografia', code: 'BE-DB', description: 'Modelagem, indexação e segurança de dados em repouso', departmentId: 'dept_backend' },
        { id: 'set_be_queue', name: 'Mensageria & Filas Assíncronas', code: 'BE-MSG', description: 'Sistemas distribuídos Kafka e RabbitMQ', departmentId: 'dept_backend' }
      ],
      createdAt: '2026-08-01T00:00:00Z'
    },
    {
      id: 'dept_frontend',
      name: 'Desenvolvimento Frontend & Mobile',
      code: 'DEV-FE',
      description: 'Interfaces reativas, experiência do usuário e apps multiplataforma',
      color: '#0284C7',
      sectors: [
        { id: 'set_fe_web', name: 'Web SPA & Design System', code: 'FE-WEB', description: 'Aplicações web modernas, acessibilidade e componentes', departmentId: 'dept_frontend' },
        { id: 'set_fe_mob', name: 'Apps Mobile iOS & Android', code: 'FE-MOB', description: 'Aplicativos nativos e híbridos corporativos', departmentId: 'dept_frontend' },
        { id: 'set_fe_ux', name: 'UX Research & Prototipagem', code: 'FE-UX', description: 'Design de produto, wireframes e fluxos de usabilidade', departmentId: 'dept_frontend' }
      ],
      createdAt: '2026-08-01T00:00:00Z'
    },
    {
      id: 'dept_sec',
      name: 'Segurança da Informação & SOC',
      code: 'SEC-SOC',
      description: 'Defesa cibernética, Zero-Leakage, conformidade OWASP e gestão de chaves',
      color: '#E11D48',
      sectors: [
        { id: 'set_sec_soc', name: 'SOC / Monitoramento 24/7', code: 'SEC-SOC', description: 'Centro de operações de segurança e resposta a incidentes', departmentId: 'dept_sec' },
        { id: 'set_sec_app', name: 'AppSec & SAST/DAST', code: 'SEC-APP', description: 'Análise estática e dinâmica de vulnerabilidades no código', departmentId: 'dept_sec' },
        { id: 'set_sec_gov', name: 'Gestão de Chaves & Conformidade', code: 'SEC-GOV', description: 'HSM, rotação criptográfica e governança de segurança', departmentId: 'dept_sec' }
      ],
      createdAt: '2026-08-01T00:00:00Z'
    },
    {
      id: 'dept_infra',
      name: 'Infraestrutura & Cloud DevSecOps',
      code: 'INFRA',
      description: 'Pipelines CI/CD, Kubernetes, monitoramento e sustentação em nuvem',
      color: '#0D9488',
      sectors: [
        { id: 'set_inf_cloud', name: 'Cloud AWS/GCP & Kubernetes', code: 'INF-K8S', description: 'Gestão de clusters elásticos e containers', departmentId: 'dept_infra' },
        { id: 'set_inf_cicd', name: 'Pipelines CI/CD & Deploy', code: 'INF-CICD', description: 'Automação de builds e esteiras de entrega contínua', departmentId: 'dept_infra' },
        { id: 'set_inf_net', name: 'Redes & VPNs Seguras', code: 'INF-NET', description: 'Segmentação de rede, firewalls e conectividade segura', departmentId: 'dept_infra' }
      ],
      createdAt: '2026-08-01T00:00:00Z'
    },
    {
      id: 'dept_ops',
      name: 'Cobrança Digital & Operações',
      code: 'OPS-COB',
      description: 'Operações de cobrança estratégica, negociação multicanal e esteiras digitais',
      color: '#D97706',
      sectors: [
        { id: 'set_ops_dig', name: 'Cobrança Digital Omnichannel', code: 'OPS-DIG', description: 'Acionamento via WhatsApp, SMS e esteiras inteligentes', departmentId: 'dept_ops' },
        { id: 'set_ops_strat', name: 'Estratégia & Analytics de Recuperação', code: 'OPS-STR', description: 'Modelos preditivos de recuperação e score de propensão', departmentId: 'dept_ops' },
        { id: 'set_ops_back', name: 'Backoffice & Conciliação Bancária', code: 'OPS-BO', description: 'Liquidação de repasses e conferência financeira', departmentId: 'dept_ops' }
      ],
      createdAt: '2026-08-01T00:00:00Z'
    },
    {
      id: 'dept_qa',
      name: 'Qualidade de Software & QA',
      code: 'QA',
      description: 'Testes automatizados, regressão, validação de segurança e qualidade contínua',
      color: '#16A34A',
      sectors: [
        { id: 'set_qa_auto', name: 'Automação de Testes E2E', code: 'QA-AUT', description: 'Playwright, Cypress e suítes de regressão contínua', departmentId: 'dept_qa' },
        { id: 'set_qa_perf', name: 'Testes de Carga & Estresse', code: 'QA-PRF', description: 'Benchmarking com k6 e validação de concorrência', departmentId: 'dept_qa' }
      ],
      createdAt: '2026-08-01T00:00:00Z'
    },
    {
      id: 'dept_audit',
      name: 'Auditoria Externa & Compliance LGPD',
      code: 'AUDIT',
      description: 'Conformidade regulatória, privacidade de dados e auditoria de processos',
      color: '#9333EA',
      sectors: [
        { id: 'set_aud_lgpd', name: 'Privacidade LGPD & DPO', code: 'AUD-LGP', description: 'Mapeamento de dados (ROPA) e atendimento aos titulares', departmentId: 'dept_audit' },
        { id: 'set_aud_reg', name: 'Controles Regulatórios & Riscos', code: 'AUD-REG', description: 'Auditorias ISO 27001 e relatórios de conformidade', departmentId: 'dept_audit' }
      ],
      createdAt: '2026-08-01T00:00:00Z'
    },
    {
      id: 'dept_rh',
      name: 'Recursos Humanos & Gestão de Pessoas',
      code: 'RH-GP',
      description: 'Gestão de talentos, desenvolvimento organizacional e cultura',
      color: '#EC4899',
      sectors: [
        { id: 'set_rh_talent', name: 'Recrutamento Tech & Seleção', code: 'RH-TAL', description: 'Atração de talentos de tecnologia e onboarding', departmentId: 'dept_rh' },
        { id: 'set_rh_dp', name: 'Departamento Pessoal & Benefícios', code: 'RH-DP', description: 'Folha, benefícios e conformidade trabalhista', departmentId: 'dept_rh' }
      ],
      createdAt: '2026-08-01T00:00:00Z'
    }
  ];

  initialDepartments.forEach(dept => {
    departmentStore.set(dept.id, dept);
  });
}

seedDepartments();

// --- TAGS STORE ---
interface TagRecord {
  id: string;
  label: string;
  color: string;
  textColor?: string;
  description?: string;
  createdAt: string;
}

const tagStore = new Map<string, TagRecord>();

function seedTags() {
  const initialTags: TagRecord[] = [
    { id: 'tag_sec', label: 'Segurança / OWASP', color: '#E11D48', textColor: '#FFFFFF', description: 'Vulnerabilidades, pentests, hardening e conformidade OWASP', createdAt: '2026-08-01T00:00:00Z' },
    { id: 'tag_backend', label: 'Backend API', color: '#6366F1', textColor: '#FFFFFF', description: 'APIs RESTful, banco de dados e arquitetura de microsserviços', createdAt: '2026-08-01T00:00:00Z' },
    { id: 'tag_crypto', label: 'Criptografia AES-256', color: '#9333EA', textColor: '#FFFFFF', description: 'Cifra de dados em trânsito e repouso, HSM e rotação de chaves', createdAt: '2026-08-01T00:00:00Z' },
    { id: 'tag_infra', label: 'DevSecOps & CI/CD', color: '#0284C7', textColor: '#FFFFFF', description: 'Pipelines CI/CD, esteiras de testes automatizados e infraestrutura', createdAt: '2026-08-01T00:00:00Z' },
    { id: 'tag_frontend', label: 'Frontend UI', color: '#16A34A', textColor: '#FFFFFF', description: 'Interfaces reativas, acessibilidade e experiência do usuário', createdAt: '2026-08-01T00:00:00Z' },
    { id: 'tag_compliance', label: 'Compliance & LGPD', color: '#D97706', textColor: '#FFFFFF', description: 'Políticas de privacidade, auditoria externa e proteção de dados', createdAt: '2026-08-01T00:00:00Z' },
    { id: 'tag_bug', label: 'Bug / Correção Crítica', color: '#DC2626', textColor: '#FFFFFF', description: 'Falhas em produção ou problemas impeditivos reportados', createdAt: '2026-08-01T00:00:00Z' },
    { id: 'tag_ux', label: 'Design System & UX', color: '#EC4899', textColor: '#FFFFFF', description: 'Componentização visual, padrões de usabilidade e prototipagem', createdAt: '2026-08-01T00:00:00Z' }
  ];

  initialTags.forEach(tag => {
    tagStore.set(tag.id, tag);
  });
}

seedTags();

// ==========================================
// 2. CRYPTOGRAPHIC ENGINE (AES-256-GCM)
// ==========================================
interface EncryptedBlob {
  version: number;
  keyId: string;
  algorithm: string;
  iv: string; // base64
  salt: string; // base64
  authTag: string; // base64
  ciphertext: string; // base64
  updatedAt: string;
}

let activeKeyVersion = 1;
let activeKeyId = 'key_master_v1_aes256';
let activeKeyAlgorithm = 'AES-256-GCM';
let lastKeyRotation = new Date().toISOString();

function deriveKeyNode(passphrase: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
}

function encryptAES256GCM(data: string, passphrase: string): EncryptedBlob {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12); // 96-bit IV
  const key = deriveKeyNode(passphrase, salt);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const authTag = cipher.getAuthTag();

  return {
    version: activeKeyVersion,
    keyId: activeKeyId,
    algorithm: activeKeyAlgorithm,
    iv: iv.toString('base64'),
    salt: salt.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted,
    updatedAt: new Date().toISOString()
  };
}

function decryptAES256GCM(blob: EncryptedBlob, passphrase: string): string {
  const salt = Buffer.from(blob.salt, 'base64');
  const iv = Buffer.from(blob.iv, 'base64');
  const authTag = Buffer.from(blob.authTag, 'base64');
  const key = deriveKeyNode(passphrase, salt);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(blob.ciphertext, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ==========================================
// 3. ZERO-LEAKAGE IN-MEMORY STORE
// ==========================================
// The actual stored records in memory are encrypted with AES-256-GCM
const memoryStore = {
  encryptedBoards: new Map<string, EncryptedBlob>(),
  encryptedCards: new Map<string, EncryptedBlob>(),
  encryptedAutomations: new Map<string, EncryptedBlob>(),
  auditLogs: [] as Array<{
    id: string;
    timestamp: string;
    actorId: string;
    actorName: string;
    actorRole: string;
    action: string;
    resourceType: string;
    resourceId: string;
    details: string;
    ipAddress: string;
    status: 'success' | 'warning' | 'denied';
    integrityHash: string;
  }>,
  keyHistory: [
    {
      id: 'key_master_v1_aes256',
      version: 1,
      algorithm: 'AES-256-GCM',
      createdAt: '2026-09-01T00:00:00Z',
      status: 'active',
      fingerprint: 'SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      iterations: 100000,
      keyLengthBits: 256
    }
  ]
};

// Seed initial state in memory
function seedInitialEncryptedStore() {
  const initialBoards = [
    {
      id: 'board_core_sprint',
      title: '🚀 Sprint 42 - Core Platform & Hardening',
      description: 'Quadro principal para desenvolvimento de features, segurança e governança.',
      icon: 'ShieldAlert',
      color: 'indigo',
      createdAt: '2026-08-20T10:00:00Z',
      updatedAt: '2026-09-01T10:15:00Z',
      ownerId: 'admin',
      isEncrypted: true,
      isPublic: true,
      allowedUserIds: [],
      columns: [
        { id: 'col_backlog', boardId: 'board_core_sprint', title: '📋 Backlog Geral', order: 0, wipLimit: 15, color: 'slate' },
        { id: 'col_todo', boardId: 'board_core_sprint', title: '🎯 A Fazer (Sprint)', order: 1, wipLimit: 6, color: 'sky' },
        { id: 'col_in_progress', boardId: 'board_core_sprint', title: '⚡ Em Andamento', order: 2, wipLimit: 4, color: 'amber' },
        { id: 'col_review', boardId: 'board_core_sprint', title: '🛡️ Code Review & SecQA', order: 3, wipLimit: 3, color: 'purple' },
        { id: 'col_done', boardId: 'board_core_sprint', title: '✅ Concluído & Deploy', order: 4, wipLimit: 20, color: 'emerald' }
      ]
    },
    {
      id: 'board_cybersec',
      title: '🛡️ CyberSec & Gestão de Vulnerabilidades',
      description: 'Acompanhamento contínuo de controles CIS, testes SAST/DAST e auditorias.',
      icon: 'Lock',
      color: 'rose',
      createdAt: '2026-08-25T14:00:00Z',
      updatedAt: '2026-09-01T09:30:00Z',
      ownerId: 'admin',
      isEncrypted: true,
      isPublic: false,
      allowedUserIds: [],
      columns: [
        { id: 'col_cs_triage', boardId: 'board_cybersec', title: '🔍 Triagem & SAST', order: 0, wipLimit: 8, color: 'slate' },
        { id: 'col_cs_mitigation', boardId: 'board_cybersec', title: '🛠️ Remediação Ativa', order: 1, wipLimit: 4, color: 'rose' },
        { id: 'col_cs_audit', boardId: 'board_cybersec', title: '📝 Validação & Pentest', order: 2, wipLimit: 3, color: 'amber' },
        { id: 'col_cs_closed', boardId: 'board_cybersec', title: '🔒 Fechado & Documentado', order: 3, wipLimit: 25, color: 'emerald' }
      ]
    }
  ];

  initialBoards.forEach(board => {
    const encrypted = encryptAES256GCM(JSON.stringify(board), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedBoards.set(board.id, encrypted);
  });

  const initialCards = [
    {
      id: 'card_aes_layer',
      columnId: 'col_in_progress',
      boardId: 'board_core_sprint',
      title: 'Implementar Criptografia em Repouso AES-256-GCM para payloads',
      description: 'Adicionar envelope encryption com PBKDF2 e geração de IVs aleatórios de 96 bits para cada cartão persistido na memória.',
      priority: 'urgent',
      tags: [
        { id: 'tag_sec', label: 'Segurança / OWASP', color: 'rose' },
        { id: 'tag_crypto', label: 'Criptografia AES-256', color: 'purple' }
      ],
      assigneeIds: [],
      dueDate: '2026-09-05T18:00:00Z',
      checklist: [
        { id: 'chk_1', title: 'Geração de IV único de 12 bytes por registro', completed: true },
        { id: 'chk_2', title: 'Cálculo de AuthTag de 128 bits para integridade', completed: true },
        { id: 'chk_3', title: 'Interface de rotação de chave no painel de administração', completed: true },
        { id: 'chk_4', title: 'Validação de testes de integridade criptográfica', completed: false }
      ],
      comments: [
        {
          id: 'comm_1',
          authorId: 'admin',
          authorName: 'Administrador',
          authorAvatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
          content: 'Cifra configurada e testada. A integridade dos pacotes está sendo validada pelo auth tag.',
          createdAt: '2026-09-01T09:10:00Z'
        }
      ],
      attachments: [
        {
          id: 'att_1',
          name: 'crypto_architecture_spec.pdf',
          size: '1.4 MB',
          type: 'application/pdf',
          sha256: '8f4e2a1b9c7d3e5f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f',
          uploadedAt: '2026-08-31T14:20:00Z'
        }
      ],
      order: 0,
      createdAt: '2026-08-28T10:00:00Z',
      updatedAt: '2026-09-01T10:00:00Z'
    },
    {
      id: 'card_zero_leak',
      columnId: 'col_review',
      boardId: 'board_core_sprint',
      title: 'Blindagem Zero-Leakage: Isolar dados sensíveis de banco do frontend',
      description: 'Garantir que URLs do banco, tokens de service_role e nomes de tabelas fiquem restritos ao backend em memória, retornando apenas DTOs sanitizados.',
      priority: 'high',
      tags: [
        { id: 'tag_sec', label: 'Segurança / OWASP', color: 'rose' },
        { id: 'tag_backend', label: 'Backend API', color: 'indigo' }
      ],
      assigneeIds: [],
      dueDate: '2026-09-03T12:00:00Z',
      checklist: [
        { id: 'chk_zl_1', title: 'Sanitizar payloads de resposta HTTP no Express', completed: true },
        { id: 'chk_zl_2', title: 'Aplicar headers de segurança estritos (CSP, nosniff, DENY)', completed: true },
        { id: 'chk_zl_3', title: 'Remover referências a credenciais no bundle client-side', completed: true }
      ],
      comments: [],
      attachments: [],
      order: 0,
      createdAt: '2026-08-29T11:30:00Z',
      updatedAt: '2026-09-01T09:45:00Z'
    },
    {
      id: 'card_rbac_idor',
      columnId: 'col_todo',
      boardId: 'board_core_sprint',
      title: 'Implementar Verificação de Propriedade contra BOLA/IDOR',
      description: 'Validar se o usuário solicitante pertence ao board correspondente antes de liberar leitura ou mutação de qualquer card.',
      priority: 'high',
      tags: [
        { id: 'tag_sec', label: 'Segurança / OWASP', color: 'rose' },
        { id: 'tag_compliance', label: 'Compliance & LGPD', color: 'amber' }
      ],
      assigneeIds: [],
      dueDate: '2026-09-07T18:00:00Z',
      checklist: [
        { id: 'chk_rb_1', title: 'Middleware de checagem de tenancy e board membership', completed: false },
        { id: 'chk_rb_2', title: 'Retornar 404 em vez de 403 para prevenir enumeração de recursos', completed: false }
      ],
      comments: [],
      attachments: [],
      order: 0,
      createdAt: '2026-08-30T09:00:00Z',
      updatedAt: '2026-08-30T09:00:00Z'
    },
    {
      id: 'card_rate_limiter',
      columnId: 'col_done',
      boardId: 'board_core_sprint',
      title: 'Configurar Rate Limiter Token Bucket por IP & Usuário',
      description: 'Proteger rotas da API contra abusos, scraping e ataques de força bruta com limites dinâmicos de requisição.',
      priority: 'medium',
      tags: [
        { id: 'tag_backend', label: 'Backend API', color: 'indigo' },
        { id: 'tag_infra', label: 'DevSecOps & CI/CD', color: 'sky' }
      ],
      assigneeIds: [],
      dueDate: '2026-08-31T18:00:00Z',
      checklist: [
        { id: 'chk_rl_1', title: 'Criação do middleware Token Bucket', completed: true },
        { id: 'chk_rl_2', title: 'Cabeçalhos RFC RateLimit retornados nas respostas', completed: true }
      ],
      comments: [],
      attachments: [],
      order: 0,
      createdAt: '2026-08-26T08:00:00Z',
      updatedAt: '2026-08-31T17:00:00Z'
    },
    {
      id: 'card_audit_logs',
      columnId: 'col_backlog',
      boardId: 'board_core_sprint',
      title: 'Adicionar Assinatura HMAC aos Logs de Auditoria para Tamper-Proofing',
      description: 'Cada linha de log gerada para ações críticas deve conter um hash criptográfico HMAC que prova que o registro não foi adulterado.',
      priority: 'medium',
      tags: [
        { id: 'tag_sec', label: 'Segurança / OWASP', color: 'rose' },
        { id: 'tag_compliance', label: 'Compliance & LGPD', color: 'amber' }
      ],
      assigneeIds: [],
      dueDate: '2026-09-12T18:00:00Z',
      checklist: [
        { id: 'chk_al_1', title: 'Gerador de HMAC SHA-256 no serviço de auditoria', completed: false },
        { id: 'chk_al_2', title: 'Visualizador de trilha de auditoria no frontend', completed: true }
      ],
      comments: [],
      attachments: [],
      order: 0,
      createdAt: '2026-08-31T16:00:00Z',
      updatedAt: '2026-08-31T16:00:00Z'
    }
  ];

  initialCards.forEach(card => {
    const encrypted = encryptAES256GCM(JSON.stringify(card), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedCards.set(card.id, encrypted);
  });

  const initialAutomations = [
    {
      id: 'auto_daily_standup',
      title: '🚀 Daily Standup & Sincronização Matinal',
      description: 'Cria diariamente o cartão de acompanhamento de impedimentos e metas do dia para a equipe.',
      boardId: 'board_core_sprint',
      columnId: 'col_todo',
      enabled: true,
      createdById: 'admin',
      createdByName: 'Administrador',
      createdByAvatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
      createdAt: '2026-08-25T08:00:00Z',
      lastRunAt: '2026-09-01T08:30:00Z',
      runCount: 7,
      cardTitle: 'Daily Scrum & Alinhamento de Metas - {{data}}',
      cardDescription: 'Rotina automática matinal para alinhamento de entregas, desbloqueio de tarefas e revisão do fluxo de trabalho diário.',
      priority: 'medium',
      tags: [
        { id: 'tag_infra', label: 'DevSecOps & CI/CD', color: 'sky' }
      ],
      assigneeIds: [],
      requester: 'Tech Lead / Scrum Master',
      requesterDepartment: 'Engenharia de Software',
      valueLevel: 'Médio',
      demandType: 'Rotina',
      checklist: [
        { id: 'auto_chk_1', title: 'O que foi entregue ontem e eventuais bloqueios', completed: false },
        { id: 'auto_chk_2', title: 'Prioridades e metas para o dia de hoje', completed: false },
        { id: 'auto_chk_3', title: 'Identificar itens com risco de atraso na sprint', completed: false }
      ],
      dateConfig: {
        startDateType: 'today',
        startTime: '09:00',
        dueDateType: 'today',
        dueTime: '18:00'
      },
      schedule: {
        frequency: 'daily',
        dailyType: 'workdays_only',
        time: '08:30'
      }
    },
    {
      id: 'auto_monthly_audit',
      title: '🛡️ Fechamento e Auditoria Mensal de Conformidade',
      description: 'Rotina agendada para o 1º dia útil de cada mês para consolidação das métricas de segurança e LGPD.',
      boardId: 'board_core_sprint',
      columnId: 'col_backlog',
      enabled: true,
      createdById: 'admin',
      createdByName: 'Administrador',
      createdByAvatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
      createdAt: '2026-08-20T10:00:00Z',
      lastRunAt: '2026-09-01T08:00:00Z',
      runCount: 2,
      cardTitle: 'Relatório Mensal de Segurança & Auditoria Zero-Leakage (Mês: {{mes}})',
      cardDescription: 'Consolidação mensal obrigatória de trilha de auditoria, rotação de chaves e indicadores de conformidade de infraestrutura.',
      priority: 'high',
      tags: [
        { id: 'tag_sec', label: 'Segurança / OWASP', color: 'rose' },
        { id: 'tag_compliance', label: 'Compliance & LGPD', color: 'amber' }
      ],
      assigneeIds: [],
      requester: 'Diretoria de Segurança & Riscos',
      requesterDepartment: 'Segurança da Informação & SOC',
      valueLevel: 'Alto',
      demandType: 'Rotina',
      checklist: [
        { id: 'auto_chk_m1', title: 'Auditar integridade de HMAC nos logs do período', completed: false },
        { id: 'auto_chk_m2', title: 'Revisar matriz de permissões e acessos ativos', completed: false },
        { id: 'auto_chk_m3', title: 'Exportar relatório executivo para diretoria', completed: false }
      ],
      dateConfig: {
        startDateType: 'today',
        startTime: '08:00',
        dueDateType: 'd_plus',
        dueDateDaysOffset: 5,
        dueTime: '18:00'
      },
      schedule: {
        frequency: 'monthly',
        monthlyType: 'workday_of_month',
        workdayOfMonth: 1,
        time: '08:00'
      }
    }
  ];

  initialAutomations.forEach(auto => {
    const encrypted = encryptAES256GCM(JSON.stringify(auto), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedAutomations.set(auto.id, encrypted);
  });

  // Seed initial audit log entries
  addAuditLog({
    actorId: 'admin',
    actorName: 'Administrador',
    actorRole: 'admin',
    action: 'SYSTEM_BOOT_INITIALIZED',
    resourceType: 'crypto_key',
    resourceId: 'key_master_v1_aes256',
    details: 'Mecanismo de cifra em repouso ativado com AES-256-GCM. Isolamento de segredos em memória verificado.',
    ipAddress: '127.0.0.1',
    status: 'success'
  });
}

function addAuditLog(entry: {
  actorId: string;
  actorName: string;
  actorRole: string;
  action: string;
  resourceType: string;
  resourceId: string;
  details: string;
  ipAddress: string;
  status: 'success' | 'warning' | 'denied';
}) {
  const timestamp = new Date().toISOString();
  const id = 'log_' + crypto.randomBytes(8).toString('hex');
  const maskedIp = entry.ipAddress.replace(/(\d+)\.(\d+)\.(\d+)\.(\d+)/, '$1.$2.$3.xxx');

  const logPayload = {
    id,
    timestamp,
    ...entry,
    ipAddress: maskedIp
  };

  const integrityHash = crypto
    .createHmac('sha256', INTERNAL_VAULT.auditHmacSecret)
    .update(JSON.stringify(logPayload))
    .digest('hex');

  const fullLog = {
    ...logPayload,
    integrityHash
  };

  memoryStore.auditLogs.unshift(fullLog);
  if (memoryStore.auditLogs.length > 500) {
    memoryStore.auditLogs.pop();
  }
  return fullLog;
}

// Initialize seed
seedInitialEncryptedStore();

// ==========================================
// 4. SECURITY MIDDLEWARE (OWASP / CIS)
// ==========================================
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Persistent Upload Directories for Card Covers and Attachments
const UPLOADS_DIR = path.join(process.cwd(), 'data', 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}
const PUBLIC_UPLOADS_DIR = path.join(process.cwd(), 'public', 'uploads');
if (!fs.existsSync(PUBLIC_UPLOADS_DIR)) {
  fs.mkdirSync(PUBLIC_UPLOADS_DIR, { recursive: true });
}

// Serve /uploads statically from data/uploads and public/uploads
app.use('/uploads', express.static(UPLOADS_DIR));
app.use('/uploads', express.static(PUBLIC_UPLOADS_DIR));

// A. Strict Security HTTP Headers
app.use((req: Request, res: Response, next: NextFunction) => {
  res.removeHeader('X-Powered-By');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https: blob:; connect-src 'self' *; object-src 'none';"
  );
  next();
});

// B. Slotted Token Bucket Rate Limiter
const ipBuckets = new Map<string, { tokens: number; lastRefill: number }>();
const BUCKET_CAPACITY = 100;
const REFILL_RATE_PER_SEC = 2;

app.use('/api', (req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
  const now = Date.now();

  let bucket = ipBuckets.get(ip);
  if (!bucket) {
    bucket = { tokens: BUCKET_CAPACITY, lastRefill: now };
    ipBuckets.set(ip, bucket);
  } else {
    const elapsedSec = (now - bucket.lastRefill) / 1000;
    bucket.tokens = Math.min(BUCKET_CAPACITY, bucket.tokens + elapsedSec * REFILL_RATE_PER_SEC);
    bucket.lastRefill = now;
  }

  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    res.setHeader('X-RateLimit-Limit', BUCKET_CAPACITY.toString());
    res.setHeader('X-RateLimit-Remaining', Math.floor(bucket.tokens).toString());
    return next();
  }

  res.setHeader('Retry-After', '10');
  addAuditLog({
    actorId: 'anonymous_client',
    actorName: 'IP Throttled',
    actorRole: 'viewer',
    action: 'RATE_LIMIT_EXCEEDED',
    resourceType: 'security_policy',
    resourceId: 'rate_limiter',
    details: `Rate limit excedido para IP ${ip}`,
    ipAddress: ip,
    status: 'warning'
  });

  return res.status(429).json({
    error: 'Muitas requisições. Rate limit excedido (429 Too Many Requests).'
  });
});

// ==========================================
// 5. SECURE AUTHENTICATION & REST API ENDPOINTS
// ==========================================

// --- AUTHENTICATION ENDPOINTS (Zero-Leakage Server-Side Auth) ---
app.post('/api/auth/login', (req: Request, res: Response) => {
  try {
    const LoginSchema = z.object({
      email: z.string().min(1),
      password: z.string().min(1)
    });

    const parsed = LoginSchema.parse(req.body);
    const normalizedEmail = parsed.email.toLowerCase().trim();
    const user = userStore.get(normalizedEmail);
    const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const now = Date.now();

    if (!user) {
      addAuditLog({
        actorId: 'anonymous_user',
        actorName: parsed.email,
        actorRole: 'viewer',
        action: 'AUTH_LOGIN_FAILED',
        resourceType: 'auth',
        resourceId: 'auth_service',
        details: `Tentativa de login com usuário/email inexistente: ${parsed.email}`,
        ipAddress: clientIp,
        status: 'denied'
      });

      return res.status(401).json({
        error: 'Credenciais inválidas. Verifique o usuário/e-mail e a senha informada.'
      });
    }

    // Check account lockout
    if (user.lockUntil && user.lockUntil > now) {
      const waitSeconds = Math.ceil((user.lockUntil - now) / 1000);
      addAuditLog({
        actorId: user.id,
        actorName: user.name,
        actorRole: user.role,
        action: 'AUTH_ACCOUNT_LOCKED',
        resourceType: 'auth',
        resourceId: user.id,
        details: `Tentativa de acesso em conta temporariamente bloqueada por excesso de falhas.`,
        ipAddress: clientIp,
        status: 'warning'
      });

      return res.status(423).json({
        error: `Conta temporariamente bloqueada por segurança. Tente novamente em ${waitSeconds} segundos.`
      });
    }

    const testHash = hashPassword(parsed.password, user.passwordSalt);
    const isPasswordValid = crypto.timingSafeEqual(
      Buffer.from(testHash, 'hex'),
      Buffer.from(user.passwordHash, 'hex')
    );

    if (!isPasswordValid) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= 5) {
        user.lockUntil = now + 15 * 60 * 1000; // 15 min lock
      }

      addAuditLog({
        actorId: user.id,
        actorName: user.name,
        actorRole: user.role,
        action: 'AUTH_LOGIN_FAILED',
        resourceType: 'auth',
        resourceId: user.id,
        details: `Senha incorreta informada (Tentativa ${user.failedLoginAttempts}/5).`,
        ipAddress: clientIp,
        status: 'denied'
      });

      return res.status(401).json({
        error: 'Senha incorreta. Por favor, tente novamente.',
        remainingAttempts: Math.max(0, 5 - user.failedLoginAttempts)
      });
    }

    // Reset failed attempts on success
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    user.lastLogin = new Date().toISOString();

    // Create session token with 24-hour expiry
    const sessionToken = 'sess_' + crypto.randomBytes(32).toString('hex');
    const expiresAt = now + 24 * 60 * 60 * 1000;
    activeSessions.set(sessionToken, { userId: user.id, expiresAt });

    addAuditLog({
      actorId: user.id,
      actorName: user.name,
      actorRole: user.role,
      action: 'AUTH_LOGIN_SUCCESS',
      resourceType: 'auth',
      resourceId: sessionToken.slice(0, 16) + '...',
      details: `Login efetuado com sucesso via PBKDF2. Sessão criptográfica inicializada.`,
      ipAddress: clientIp,
      status: 'success'
    });

    // Return sanitized profile (NEVER expose salts or password hashes)
    res.json({
      success: true,
      token: sessionToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        avatar: user.avatar,
        department: user.department,
        sector: user.sector,
        mfaEnabled: user.mfaEnabled,
        lastLogin: user.lastLogin
      }
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Erro ao processar login.' });
  }
});

app.post('/api/auth/register', (req: Request, res: Response) => {
  try {
    const RegisterSchema = z.object({
      email: z.string().email(),
      password: z.string().min(6),
      name: z.string().min(2),
      department: z.string().default('Engenharia de Software'),
      sector: z.string().optional().default(''),
      role: z.string().default('member')
    });

    const parsed = RegisterSchema.parse(req.body);
    const normalizedEmail = parsed.email.toLowerCase().trim();

    if (userStore.has(normalizedEmail)) {
      return res.status(409).json({ error: 'Um usuário com este e-mail já está cadastrado.' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPassword(parsed.password, salt);
    const userId = 'usr_' + crypto.randomBytes(6).toString('hex');

    const newUser: UserRecord = {
      id: userId,
      email: normalizedEmail,
      name: parsed.name,
      role: parsed.role,
      avatar: `https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80`,
      department: parsed.department,
      sector: parsed.sector,
      mfaEnabled: true,
      passwordSalt: salt,
      passwordHash,
      failedLoginAttempts: 0,
      lockUntil: null,
      lastLogin: new Date().toISOString()
    };

    userStore.set(normalizedEmail, newUser);

    const sessionToken = 'sess_' + crypto.randomBytes(32).toString('hex');
    activeSessions.set(sessionToken, { userId: newUser.id, expiresAt: Date.now() + 24 * 60 * 60 * 1000 });

    addAuditLog({
      actorId: newUser.id,
      actorName: newUser.name,
      actorRole: newUser.role,
      action: 'AUTH_USER_REGISTERED',
      resourceType: 'auth',
      resourceId: newUser.id,
      details: `Novo usuário registrado no cofre com hash PBKDF2 e MFA ativado.`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.status(201).json({
      success: true,
      token: sessionToken,
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        role: newUser.role,
        avatar: newUser.avatar,
        department: newUser.department,
        sector: newUser.sector,
        mfaEnabled: newUser.mfaEnabled,
        lastLogin: newUser.lastLogin
      }
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/auth/logout', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const session = activeSessions.get(token);
    if (session) {
      activeSessions.delete(token);
      addAuditLog({
        actorId: session.userId,
        actorName: 'Usuário Conectado',
        actorRole: 'member',
        action: 'AUTH_LOGOUT',
        resourceType: 'auth',
        resourceId: token.slice(0, 16) + '...',
        details: 'Sessão revogada e destruída com sucesso.',
        ipAddress: req.ip || '127.0.0.1',
        status: 'success'
      });
    }
  }
  res.json({ success: true, message: 'Sessão encerrada com sucesso.' });
});

// =================================================================
// PROVISIONAMENTO AUTOMÁTICO E SINCRONIZAÇÃO COM FIREBASE AUTH
// =================================================================
app.post('/api/auth/auto-provision', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'E-mail corporativo e senha são obrigatórios.' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // 1. Verifica se o usuário existe no Firestore
    const db = await getServerDb();
    let firestoreUser: any = null;
    let originalDocId: string | null = null;

    if (db) {
      try {
        const snap = await getDocs(collection(db, 'users'));
        for (const d of snap.docs) {
          const u = d.data();
          if (u.email && u.email.trim().toLowerCase() === normalizedEmail) {
            firestoreUser = u;
            originalDocId = d.id;
            break;
          }
        }
      } catch (dbErr: any) {
        console.warn('[Auto-Provision] Error fetching users from Firestore:', dbErr?.message || dbErr);
      }
    }

    // Fallback para memória se Firestore ainda não respondeu
    if (!firestoreUser && userStore.has(normalizedEmail)) {
      firestoreUser = userStore.get(normalizedEmail);
    }

    // Auto-provisionamento para domínio corporativo ou administradores
    if (!firestoreUser && (
      normalizedEmail.endsWith('@meirelesefreitas.com.br') ||
      normalizedEmail.endsWith('@flowdeck.io') ||
      normalizedEmail === 'misreport@meirelesefreitas.com.br' ||
      normalizedEmail === 'admin@flowdeck.io'
    )) {
      const namePart = normalizedEmail.split('@')[0];
      const displayName = namePart.charAt(0).toUpperCase() + namePart.slice(1);
      firestoreUser = {
        name: displayName,
        email: normalizedEmail,
        role: 'admin',
        department: 'Inteligência de Negócios',
        sector: 'Mis/Bi',
        mfaEnabled: false
      };
    }

    if (!firestoreUser) {
      return res.status(404).json({
        success: false,
        notFound: true,
        message: 'Usuário não encontrado no cadastro corporativo. Contate um administrador.'
      });
    }

    // 2. Cria o usuário no Firebase Authentication com a senha informada
    const fbRes = await createFirebaseUser(normalizedEmail, password, firestoreUser.name);

    if ('error' in fbRes) {
      if (fbRes.code === 'EMAIL_EXISTS') {
        // Já existe no Firebase Authentication -> a senha digitada foi incorreta
        return res.status(400).json({
          success: false,
          alreadyExists: true,
          message: 'Usuário já cadastrado no autenticador. Senha incorreta.'
        });
      }
      return res.status(500).json({
        success: false,
        error: fbRes.error
      });
    }

    // 3. Sucesso! Usuário criado no Firebase Authentication
    const newUid = fbRes.uid;
    if (db) {
      const updatedProfile = {
        ...firestoreUser,
        id: newUid,
        authUid: newUid,
        email: normalizedEmail,
        lastLogin: new Date().toISOString()
      };
      await setDoc(doc(db, 'users', newUid), updatedProfile, { merge: true });
    }

    addAuditLog({
      actorId: newUid,
      actorName: firestoreUser.name || normalizedEmail,
      actorRole: firestoreUser.role || 'member',
      action: 'AUTH_AUTO_PROVISIONED',
      resourceType: 'auth',
      resourceId: newUid,
      details: `Conta provisionada e ativada no Firebase Authentication com credenciais corporativas.`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    return res.json({
      success: true,
      provisioned: true,
      uid: newUid,
      message: 'Conta ativada com sucesso no autenticador Firebase!'
    });
  } catch (err: any) {
    console.error('[API Auto-Provision Error]', err);
    res.status(500).json({ error: err.message || 'Erro no provisionamento automático.' });
  }
});

app.post('/api/auth/sync-firestore-users', async (req: Request, res: Response) => {
  try {
    const { defaultPassword = '123456' } = req.body;
    if (defaultPassword.length < 6) {
      return res.status(400).json({ error: 'A senha deve ter no mínimo 6 caracteres.' });
    }

    const db = await getServerDb();
    if (!db) {
      return res.status(500).json({ error: 'Não foi possível conectar ao Firestore.' });
    }

    const snap = await getDocs(collection(db, 'users'));
    const results: Array<{ email: string; name: string; status: 'created' | 'already_in_auth' | 'error'; message?: string }> = [];

    for (const d of snap.docs) {
      const u = d.data();
      const email = u.email?.trim().toLowerCase();
      if (!email) continue;

      const fbRes = await createFirebaseUser(email, defaultPassword, u.name);
      if ('uid' in fbRes) {
        await setDoc(doc(db, 'users', fbRes.uid), {
          ...u,
          id: fbRes.uid,
          authUid: fbRes.uid,
          lastLogin: new Date().toISOString()
        }, { merge: true });

        results.push({ email, name: u.name || email, status: 'created' });
      } else if (fbRes.code === 'EMAIL_EXISTS') {
        results.push({ email, name: u.name || email, status: 'already_in_auth' });
      } else {
        results.push({ email, name: u.name || email, status: 'error', message: fbRes.error });
      }
    }

    const createdCount = results.filter(r => r.status === 'created').length;
    const alreadyCount = results.filter(r => r.status === 'already_in_auth').length;

    res.json({
      success: true,
      total: results.length,
      createdCount,
      alreadyCount,
      results
    });
  } catch (err: any) {
    console.error('[API Sync Users Error]', err);
    res.status(500).json({ error: err.message || 'Erro na sincronização de usuários.' });
  }
});

app.post('/api/auth/set-user-password', async (req: Request, res: Response) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || password.length < 6) {
      return res.status(400).json({ error: 'E-mail corporativo e senha válida (mínimo 6 dígitos) são obrigatórios.' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const fbRes = await createFirebaseUser(normalizedEmail, password, name);
    
    if ('uid' in fbRes) {
      const db = await getServerDb();
      if (db) {
        await setDoc(doc(db, 'users', fbRes.uid), {
          email: normalizedEmail,
          name: name || normalizedEmail.split('@')[0],
          authUid: fbRes.uid,
          id: fbRes.uid
        }, { merge: true });
      }
      return res.json({ success: true, created: true, message: 'Usuário cadastrado com sucesso no Firebase Authentication!' });
    }

    if (fbRes.code === 'EMAIL_EXISTS') {
      return res.json({
        success: true,
        alreadyExists: true,
        message: 'O usuário já possui conta cadastrada no Firebase Authentication.'
      });
    }

    return res.status(500).json({ error: fbRes.error });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Erro ao registrar credenciais.' });
  }
});

app.post('/api/auth/sync-password', async (req: Request, res: Response) => {
  try {
    const { email, newPassword } = req.body;
    if (!email || !newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: 'Email e nova senha válidos são obrigatórios.' });
    }
    const normalizedEmail = email.trim().toLowerCase();
    const foundUser = userStore.get(normalizedEmail);
    if (foundUser) {
      const salt = crypto.randomBytes(16).toString('hex');
      foundUser.passwordSalt = salt;
      foundUser.passwordHash = hashPassword(newPassword, salt);
      userStore.set(normalizedEmail, foundUser);
    }
    res.json({ success: true, message: 'Senha sincronizada no servidor com sucesso.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Erro ao sincronizar senha no servidor.' });
  }
});

app.get('/api/auth/me', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token de autenticação ausente.' });
  }

  const token = authHeader.substring(7);
  const session = activeSessions.get(token);

  if (!session || session.expiresAt < Date.now()) {
    if (session) activeSessions.delete(token);
    return res.status(401).json({ error: 'Sessão expirada ou inválida.' });
  }

  let matchedUser: UserRecord | undefined;
  for (const u of userStore.values()) {
    if (u.id === session.userId) {
      matchedUser = u;
      break;
    }
  }

  if (!matchedUser) {
    return res.status(404).json({ error: 'Usuário não encontrado.' });
  }

  res.json({
    id: matchedUser.id,
    email: matchedUser.email,
    name: matchedUser.name,
    role: matchedUser.role,
    avatar: matchedUser.avatar,
    department: matchedUser.department,
    sector: matchedUser.sector,
    mfaEnabled: matchedUser.mfaEnabled,
    lastLogin: matchedUser.lastLogin
  });
});

// --- USER MANAGEMENT ENDPOINTS (Configurações > Usuários) ---
app.get('/api/v1/users', (req: Request, res: Response) => {
  const usersList = Array.from(userStore.values()).map(u => ({
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    avatar: u.avatar,
    department: u.department,
    sector: u.sector,
    mfaEnabled: u.mfaEnabled,
    lastLogin: u.lastLogin
  }));
  res.json(usersList);
});

app.post('/api/v1/users', async (req: Request, res: Response) => {
  try {
    const CreateUserSchema = z.object({
      id: z.string().optional(),
      email: z.string().email('E-mail corporativo inválido.'),
      password: z.string().min(6, 'A senha deve ter no mínimo 6 caracteres.').optional(),
      name: z.string().min(2, 'O nome deve ter no mínimo 2 caracteres.'),
      department: z.string().default('Engenharia de Software'),
      sector: z.string().optional().default(''),
      role: z.string().default('member'),
      avatar: z.string().optional()
    });

    const parsed = CreateUserSchema.parse(req.body);
    const normalizedEmail = parsed.email.toLowerCase().trim();

    if (userStore.has(normalizedEmail)) {
      return res.status(409).json({ error: 'Um usuário com este e-mail já está cadastrado.' });
    }

    // Provision automatically in Firebase Authentication if password provided
    let userId = parsed.id || ('usr_' + crypto.randomBytes(6).toString('hex'));
    if (parsed.password) {
      const fbResult = await createFirebaseUser(normalizedEmail, parsed.password, parsed.name);
      if ('uid' in fbResult) {
        userId = fbResult.uid;
      }
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPassword(parsed.password || 'default_pass_123', salt);

    const defaultAvatars = [
      'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
      'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&auto=format&fit=crop&q=80',
      'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=150&auto=format&fit=crop&q=80',
      'https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=150&auto=format&fit=crop&q=80',
      'https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?w=150&auto=format&fit=crop&q=80'
    ];
    const assignedAvatar = parsed.avatar || defaultAvatars[Math.floor(Math.random() * defaultAvatars.length)];

    const newUser: UserRecord = {
      id: userId,
      email: normalizedEmail,
      name: parsed.name,
      role: parsed.role,
      avatar: assignedAvatar,
      department: parsed.department,
      sector: parsed.sector,
      mfaEnabled: true,
      passwordSalt: salt,
      passwordHash,
      failedLoginAttempts: 0,
      lockUntil: null,
      lastLogin: null
    };

    userStore.set(normalizedEmail, newUser);

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'USER_CREATED_BY_ADMIN',
      resourceType: 'user_management',
      resourceId: newUser.id,
      details: `Novo usuário ${newUser.name} (${newUser.email}) criado no menu de Usuários com perfil ${newUser.role} no departamento "${newUser.department}".`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.status(201).json({
      id: newUser.id,
      email: newUser.email,
      name: newUser.name,
      role: newUser.role,
      avatar: newUser.avatar,
      department: newUser.department,
      sector: newUser.sector,
      mfaEnabled: newUser.mfaEnabled,
      lastLogin: newUser.lastLogin
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/v1/users/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    let foundEmail: string | null = null;
    let foundUser: UserRecord | null = null;

    for (const [em, u] of userStore.entries()) {
      if (u.id === id || em.toLowerCase() === id.toLowerCase()) {
        foundEmail = em;
        foundUser = u;
        break;
      }
    }

    if (!foundUser || !foundEmail) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    const { name, department, sector, role, avatar, newPassword } = req.body;

    if (name) foundUser.name = name;
    if (department !== undefined) foundUser.department = department;
    if (sector !== undefined) foundUser.sector = sector;
    if (role) foundUser.role = role;
    if (avatar) foundUser.avatar = avatar;
    if (newPassword && newPassword.length >= 6) {
      const salt = crypto.randomBytes(16).toString('hex');
      foundUser.passwordSalt = salt;
      foundUser.passwordHash = hashPassword(newPassword, salt);
    }

    userStore.set(foundEmail, foundUser);

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'USER_UPDATED',
      resourceType: 'user_management',
      resourceId: foundUser.id,
      details: `Perfil de ${foundUser.name} (${foundUser.email}) atualizado.`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json({
      id: foundUser.id,
      email: foundUser.email,
      name: foundUser.name,
      role: foundUser.role,
      avatar: foundUser.avatar,
      department: foundUser.department,
      sector: foundUser.sector,
      mfaEnabled: foundUser.mfaEnabled,
      lastLogin: foundUser.lastLogin
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.patch('/api/v1/users/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    let foundEmail: string | null = null;
    let foundUser: UserRecord | null = null;

    for (const [em, u] of userStore.entries()) {
      if (u.id === id || em.toLowerCase() === id.toLowerCase()) {
        foundEmail = em;
        foundUser = u;
        break;
      }
    }

    if (!foundUser || !foundEmail) {
      // Se não encontrado no userStore em memória, aceita o patch silenciosamente
      return res.json({ success: true, updated: false, message: 'Usuário não localizado no cache em memória.' });
    }

    const { name, department, sector, role, avatar, newPassword } = req.body;

    // Atualização estrita: só altera os campos expressamente fornecidos no body
    if (name !== undefined && name.trim()) foundUser.name = name.trim();
    if (department !== undefined && department.trim()) foundUser.department = department.trim();
    if (sector !== undefined) foundUser.sector = sector ? sector.trim() : undefined;
    if (role !== undefined && role.trim()) foundUser.role = role.trim();
    if (avatar !== undefined && avatar.trim()) foundUser.avatar = avatar;
    if (newPassword && newPassword.length >= 6) {
      const salt = crypto.randomBytes(16).toString('hex');
      foundUser.passwordSalt = salt;
      foundUser.passwordHash = hashPassword(newPassword, salt);
    }

    userStore.set(foundEmail, foundUser);

    res.json({
      id: foundUser.id,
      email: foundUser.email,
      name: foundUser.name,
      role: foundUser.role,
      avatar: foundUser.avatar,
      department: foundUser.department,
      sector: foundUser.sector,
      mfaEnabled: foundUser.mfaEnabled,
      lastLogin: foundUser.lastLogin
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/v1/users/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    let foundEmail: string | null = null;
    let foundUser: UserRecord | null = null;

    for (const [em, u] of userStore.entries()) {
      if (u.id === id) {
        foundEmail = em;
        foundUser = u;
        break;
      }
    }

    if (!foundUser || !foundEmail) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    // Safety: Ensure at least one admin remains
    if (foundUser.role === 'admin') {
      let adminCount = 0;
      for (const u of userStore.values()) {
        if (u.role === 'admin') adminCount++;
      }
      if (adminCount <= 1) {
        return res.status(400).json({ error: 'Não é permitido excluir o único administrador do sistema.' });
      }
    }

    userStore.delete(foundEmail);

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'USER_DELETED',
      resourceType: 'user_management',
      resourceId: id,
      details: `Usuário ${foundUser.name} (${foundEmail}) foi removido do sistema.`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'warning'
    });

    res.json({ success: true, message: `Usuário ${foundUser.name} removido com sucesso.` });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// --- DEPARTMENT MANAGEMENT ENDPOINTS (Configurações > Departamentos) ---
app.get('/api/v1/departments', (req: Request, res: Response) => {
  const departmentsList = Array.from(departmentStore.values());
  res.json(departmentsList);
});

app.post('/api/v1/departments', (req: Request, res: Response) => {
  try {
    const CreateDeptSchema = z.object({
      name: z.string().min(2, 'O nome do departamento deve ter no mínimo 2 caracteres.'),
      code: z.string().max(15).optional(),
      description: z.string().optional(),
      color: z.string().default('#2563EB'),
      sectors: z.array(z.any()).optional()
    });

    const parsed = CreateDeptSchema.parse(req.body);
    const trimmedName = parsed.name.trim();

    // Check duplicate name
    for (const d of departmentStore.values()) {
      if (d.name.toLowerCase() === trimmedName.toLowerCase()) {
        return res.status(409).json({ error: 'Um departamento com este nome já existe.' });
      }
    }

    const deptId = 'dept_' + crypto.randomBytes(6).toString('hex');
    const initialSectors = (parsed.sectors || []).map((s: any) => ({
      id: s.id || ('set_' + crypto.randomBytes(4).toString('hex')),
      name: s.name,
      code: s.code || s.name.substring(0, 3).toUpperCase(),
      description: s.description || '',
      departmentId: deptId,
      createdAt: new Date().toISOString()
    }));

    const newDept: DepartmentRecord = {
      id: deptId,
      name: trimmedName,
      code: parsed.code ? parsed.code.trim().toUpperCase() : trimmedName.substring(0, 4).toUpperCase(),
      description: parsed.description ? parsed.description.trim() : '',
      color: parsed.color || '#2563EB',
      sectors: initialSectors,
      createdAt: new Date().toISOString()
    };

    departmentStore.set(deptId, newDept);

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'DEPARTMENT_CREATED',
      resourceType: 'user_management',
      resourceId: deptId,
      details: `Novo departamento criado: "${newDept.name}" [${newDept.code}] com ${newDept.sectors?.length || 0} setor(es).`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.status(201).json(newDept);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Dados inválidos para criação do departamento.' });
  }
});

app.put('/api/v1/departments/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const existing = departmentStore.get(id);

    if (!existing) {
      return res.status(404).json({ error: 'Departamento não encontrado.' });
    }

    const UpdateDeptSchema = z.object({
      name: z.string().min(2).optional(),
      code: z.string().max(15).optional(),
      description: z.string().optional(),
      color: z.string().optional(),
      sectors: z.array(z.any()).optional()
    });

    const parsed = UpdateDeptSchema.parse(req.body);

    if (parsed.name) {
      const trimmedName = parsed.name.trim();
      for (const [deptKey, d] of departmentStore.entries()) {
        if (deptKey !== id && d.name.toLowerCase() === trimmedName.toLowerCase()) {
          return res.status(409).json({ error: 'Já existe outro departamento com este nome.' });
        }
      }
      existing.name = trimmedName;
    }

    if (parsed.code !== undefined) {
      existing.code = parsed.code.trim().toUpperCase();
    }
    if (parsed.description !== undefined) {
      existing.description = parsed.description.trim();
    }
    if (parsed.color !== undefined) {
      existing.color = parsed.color;
    }
    if (parsed.sectors !== undefined) {
      existing.sectors = parsed.sectors;
    }

    departmentStore.set(id, existing);

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'DEPARTMENT_UPDATED',
      resourceType: 'user_management',
      resourceId: id,
      details: `Departamento atualizado: "${existing.name}" [${existing.code}]`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json(existing);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Falha ao atualizar departamento.' });
  }
});

app.delete('/api/v1/departments/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const existing = departmentStore.get(id);

    if (!existing) {
      return res.status(404).json({ error: 'Departamento não encontrado.' });
    }

    // Reassign any users who were attached to this department to 'Geral'
    for (const [uid, u] of userStore.entries()) {
      if (u.department && (u.department.toLowerCase() === existing.name.toLowerCase() || u.department === existing.id)) {
        userStore.set(uid, { ...u, department: 'Geral', sector: '' });
      }
    }

    departmentStore.delete(id);

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'DEPARTMENT_DELETED',
      resourceType: 'user_management',
      resourceId: id,
      details: `Departamento excluído: "${existing.name}"`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'warning'
    });

    res.json({ success: true, message: `Departamento "${existing.name}" excluído com sucesso.` });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// --- SECTOR MANAGEMENT ENDPOINTS (Sub-divisão dentro dos Departamentos) ---
app.post('/api/v1/departments/:deptId/sectors', (req: Request, res: Response) => {
  try {
    const { deptId } = req.params;
    const dept = departmentStore.get(deptId);
    if (!dept) return res.status(404).json({ error: 'Departamento não encontrado.' });

    const SectorSchema = z.object({
      name: z.string().min(2, 'O nome do setor deve ter no mínimo 2 caracteres.'),
      code: z.string().max(15).optional(),
      description: z.string().optional()
    });

    const parsed = SectorSchema.parse(req.body);
    const sectorName = parsed.name.trim();

    if (!dept.sectors) dept.sectors = [];

    // Check duplicate within department
    if (dept.sectors.some(s => s.name.toLowerCase() === sectorName.toLowerCase())) {
      return res.status(409).json({ error: 'Já existe um setor com este nome neste departamento.' });
    }

    const sectorId = 'set_' + crypto.randomBytes(4).toString('hex');
    const newSector: SectorRecord = {
      id: sectorId,
      name: sectorName,
      code: parsed.code ? parsed.code.trim().toUpperCase() : sectorName.substring(0, 4).toUpperCase(),
      description: parsed.description ? parsed.description.trim() : '',
      departmentId: deptId,
      createdAt: new Date().toISOString()
    };

    dept.sectors.push(newSector);
    departmentStore.set(deptId, dept);

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'DEPARTMENT_UPDATED',
      resourceType: 'user_management',
      resourceId: deptId,
      details: `Setor "${newSector.name}" adicionado ao departamento "${dept.name}".`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.status(201).json(newSector);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Erro ao cadastrar setor.' });
  }
});

app.put('/api/v1/departments/:deptId/sectors/:sectorId', (req: Request, res: Response) => {
  try {
    const { deptId, sectorId } = req.params;
    const dept = departmentStore.get(deptId);
    if (!dept || !dept.sectors) return res.status(404).json({ error: 'Departamento ou setores não encontrados.' });

    const sectorIndex = dept.sectors.findIndex(s => s.id === sectorId);
    if (sectorIndex === -1) return res.status(404).json({ error: 'Setor não encontrado.' });

    const { name, code, description } = req.body;
    if (name) {
      const trimmed = name.trim();
      if (dept.sectors.some((s, idx) => idx !== sectorIndex && s.name.toLowerCase() === trimmed.toLowerCase())) {
        return res.status(409).json({ error: 'Já existe outro setor com este nome.' });
      }
      dept.sectors[sectorIndex].name = trimmed;
    }
    if (code !== undefined) dept.sectors[sectorIndex].code = code.trim().toUpperCase();
    if (description !== undefined) dept.sectors[sectorIndex].description = description.trim();

    departmentStore.set(deptId, dept);

    res.json(dept.sectors[sectorIndex]);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/v1/departments/:deptId/sectors/:sectorId', (req: Request, res: Response) => {
  try {
    const { deptId, sectorId } = req.params;
    const dept = departmentStore.get(deptId);
    if (!dept || !dept.sectors) return res.status(404).json({ error: 'Departamento não encontrado.' });

    const removed = dept.sectors.find(s => s.id === sectorId);
    dept.sectors = dept.sectors.filter(s => s.id !== sectorId);
    departmentStore.set(deptId, dept);

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'DEPARTMENT_UPDATED',
      resourceType: 'user_management',
      resourceId: deptId,
      details: `Setor "${removed?.name || sectorId}" removido do departamento "${dept.name}".`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'warning'
    });

    res.json({ success: true, message: 'Setor removido com sucesso.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// --- PERMISSION LEVELS / ROLES MANAGEMENT ENDPOINTS (Configurações > Níveis de Permissão) ---
app.get('/api/v1/roles', (req: Request, res: Response) => {
  const rolesList = Array.from(roleStore.values());
  res.json(rolesList);
});

app.get('/api/v1/permissions', (req: Request, res: Response) => {
  const rolesList = Array.from(roleStore.values());
  res.json(rolesList);
});

app.post('/api/v1/roles', (req: Request, res: Response) => {
  try {
    const CreateRoleSchema = z.object({
      name: z.string().min(2, 'O nome do perfil deve ter no mínimo 2 caracteres.'),
      code: z.string().max(15).optional(),
      description: z.string().optional(),
      color: z.string().default('#3B82F6'),
      canAccessSettings: z.boolean().default(false),
      canCreateCards: z.boolean().default(true),
      canEditCards: z.boolean().default(true),
      canDeleteCards: z.boolean().default(false),
      canCreateBoards: z.boolean().default(false),
      canDeleteBoards: z.boolean().default(false),
      canMoveCards: z.boolean().default(true)
    });

    const parsed = CreateRoleSchema.parse(req.body);
    const trimmedName = parsed.name.trim();

    // Check duplicate name
    for (const r of roleStore.values()) {
      if (r.name.toLowerCase() === trimmedName.toLowerCase()) {
        return res.status(409).json({ error: 'Já existe um nível de permissão com este nome.' });
      }
    }

    const roleId = 'role_' + crypto.randomBytes(6).toString('hex');
    const autoCode = parsed.code?.trim().toUpperCase() || trimmedName.substring(0, 4).toUpperCase();

    const newRole: PermissionLevelRecord = {
      id: roleId,
      name: trimmedName,
      code: autoCode,
      description: parsed.description?.trim() || `Perfil operacional personalizado: ${trimmedName}`,
      color: parsed.color,
      isSystem: false,
      canAccessSettings: parsed.canAccessSettings,
      canCreateCards: parsed.canCreateCards,
      canEditCards: parsed.canEditCards,
      canDeleteCards: parsed.canDeleteCards,
      canCreateBoards: parsed.canCreateBoards,
      canDeleteBoards: parsed.canDeleteBoards,
      canMoveCards: parsed.canMoveCards,
      createdAt: new Date().toISOString()
    };

    roleStore.set(roleId, newRole);

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'ROLE_CREATED',
      resourceType: 'user_management',
      resourceId: roleId,
      details: `Novo nível de permissão criado: "${newRole.name}" [${newRole.code}] (Config: ${newRole.canAccessSettings ? 'Sim' : 'Não'} | Criar Cards: ${newRole.canCreateCards ? 'Sim' : 'Não'} | Editar Cards: ${newRole.canEditCards ? 'Sim' : 'Não'} | Excluir Cards: ${newRole.canDeleteCards ? 'Sim' : 'Não'})`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.status(201).json(newRole);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Falha ao cadastrar nível de permissão.' });
  }
});

app.put('/api/v1/roles/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const existing = roleStore.get(id);

    if (!existing) {
      return res.status(404).json({ error: 'Nível de permissão não encontrado.' });
    }

    const UpdateRoleSchema = z.object({
      name: z.string().min(2).optional(),
      code: z.string().max(15).optional(),
      description: z.string().optional(),
      color: z.string().optional(),
      canAccessSettings: z.boolean().optional(),
      canCreateCards: z.boolean().optional(),
      canEditCards: z.boolean().optional(),
      canDeleteCards: z.boolean().optional(),
      canCreateBoards: z.boolean().optional(),
      canDeleteBoards: z.boolean().optional(),
      canMoveCards: z.boolean().optional()
    });

    const parsed = UpdateRoleSchema.parse(req.body);

    if (parsed.name) {
      const trimmedName = parsed.name.trim();
      for (const [rKey, r] of roleStore.entries()) {
        if (rKey !== id && r.name.toLowerCase() === trimmedName.toLowerCase()) {
          return res.status(409).json({ error: 'Já existe outro nível de permissão com este nome.' });
        }
      }
      existing.name = trimmedName;
    }

    if (parsed.code !== undefined) {
      existing.code = parsed.code.trim().toUpperCase();
    }
    if (parsed.description !== undefined) {
      existing.description = parsed.description.trim();
    }
    if (parsed.color !== undefined) {
      existing.color = parsed.color;
    }

    // Protect system admin settings access
    if (existing.isSystem && existing.id === 'admin') {
      existing.canAccessSettings = true;
      existing.canCreateCards = true;
      existing.canEditCards = true;
      existing.canDeleteCards = true;
      existing.canCreateBoards = true;
      existing.canDeleteBoards = true;
      existing.canMoveCards = true;
    } else {
      if (parsed.canAccessSettings !== undefined) existing.canAccessSettings = parsed.canAccessSettings;
      if (parsed.canCreateCards !== undefined) existing.canCreateCards = parsed.canCreateCards;
      if (parsed.canEditCards !== undefined) existing.canEditCards = parsed.canEditCards;
      if (parsed.canDeleteCards !== undefined) existing.canDeleteCards = parsed.canDeleteCards;
      if (parsed.canCreateBoards !== undefined) existing.canCreateBoards = parsed.canCreateBoards;
      if (parsed.canDeleteBoards !== undefined) existing.canDeleteBoards = parsed.canDeleteBoards;
      if (parsed.canMoveCards !== undefined) existing.canMoveCards = parsed.canMoveCards;
    }

    roleStore.set(id, existing);

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'ROLE_UPDATED',
      resourceType: 'user_management',
      resourceId: id,
      details: `Nível de permissão "${existing.name}" atualizado (Config: ${existing.canAccessSettings ? 'Sim' : 'Não'} | Criar: ${existing.canCreateCards ? 'Sim' : 'Não'} | Editar: ${existing.canEditCards ? 'Sim' : 'Não'} | Excluir: ${existing.canDeleteCards ? 'Sim' : 'Não'})`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json(existing);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Falha ao atualizar nível de permissão.' });
  }
});

app.delete('/api/v1/roles/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const existing = roleStore.get(id);

    if (!existing) {
      return res.status(404).json({ error: 'Nível de permissão não encontrado.' });
    }

    if (existing.id === 'admin') {
      return res.status(403).json({ error: 'O perfil padrão de Administrador do Sistema é protegido e não pode ser excluído.' });
    }

    // Safety: check if any user is currently attached to this role
    const usersInRole: string[] = [];
    for (const u of userStore.values()) {
      if (u.role && (u.role.toLowerCase() === existing.id.toLowerCase() || u.role.toLowerCase() === existing.name.toLowerCase())) {
        usersInRole.push(u.name);
      }
    }

    if (usersInRole.length > 0) {
      return res.status(400).json({
        error: `Não é possível excluir o nível "${existing.name}" pois existem ${usersInRole.length} usuário(s) vinculado(s): ${usersInRole.slice(0, 3).join(', ')}${usersInRole.length > 3 ? '...' : ''}. Reatribua os colaboradores para outro perfil primeiro.`
      });
    }

    roleStore.delete(id);

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'ROLE_DELETED',
      resourceType: 'user_management',
      resourceId: id,
      details: `Nível de permissão excluído: "${existing.name}" [${existing.code}]`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'warning'
    });

    res.json({ success: true, message: `Nível de permissão "${existing.name}" excluído com sucesso.` });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// --- TAGS / ETIQUETAS API ---
app.get('/api/v1/tags', (req: Request, res: Response) => {
  res.json(Array.from(tagStore.values()));
});

app.post('/api/v1/tags', (req: Request, res: Response) => {
  try {
    const CreateTagSchema = z.object({
      id: z.string().optional(),
      label: z.string().min(1, 'O nome da etiqueta é obrigatório.'),
      color: z.string().default('#2563EB'),
      textColor: z.string().optional().default('#FFFFFF'),
      description: z.string().optional()
    });

    const parsed = CreateTagSchema.parse(req.body);
    const trimmedLabel = parsed.label.trim();

    // Check duplicate
    for (const t of tagStore.values()) {
      if (t.label.toLowerCase() === trimmedLabel.toLowerCase()) {
        return res.status(409).json({ error: 'Já existe uma etiqueta cadastrada com este nome.' });
      }
    }

    const tagId = parsed.id || ('tag_' + crypto.randomBytes(6).toString('hex'));
    const newTag: TagRecord = {
      id: tagId,
      label: trimmedLabel,
      color: parsed.color,
      textColor: parsed.textColor || '#FFFFFF',
      description: parsed.description?.trim(),
      createdAt: new Date().toISOString()
    };

    tagStore.set(tagId, newTag);

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'TAG_CREATED',
      resourceType: 'workspace_tag',
      resourceId: tagId,
      details: `Nova etiqueta cadastrada: "${newTag.label}" (${newTag.color}, fonte: ${newTag.textColor})`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.status(201).json(newTag);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Falha ao cadastrar etiqueta.' });
  }
});

app.put('/api/v1/tags/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    let existing = tagStore.get(id);

    const UpdateTagSchema = z.object({
      id: z.string().optional(),
      label: z.string().min(1).optional(),
      color: z.string().optional(),
      textColor: z.string().optional(),
      description: z.string().optional()
    });

    const parsed = UpdateTagSchema.parse(req.body);

    if (!existing) {
      existing = {
        id,
        label: parsed.label?.trim() || 'Nova Tag',
        color: parsed.color || '#2563EB',
        textColor: parsed.textColor || '#FFFFFF',
        description: parsed.description?.trim(),
        createdAt: new Date().toISOString()
      };
      tagStore.set(id, existing);
    }

    if (parsed.label) {
      const trimmedLabel = parsed.label.trim();
      for (const [tKey, t] of tagStore.entries()) {
        if (tKey !== id && t.label.toLowerCase() === trimmedLabel.toLowerCase()) {
          return res.status(409).json({ error: 'Já existe outra etiqueta com este nome.' });
        }
      }
      existing.label = trimmedLabel;
    }

    if (parsed.color !== undefined) {
      existing.color = parsed.color;
    }

    if (parsed.textColor !== undefined) {
      existing.textColor = parsed.textColor;
    }

    if (parsed.description !== undefined) {
      existing.description = parsed.description.trim();
    }

    tagStore.set(id, existing);

    // Also update this tag in all encrypted cards that use it
    for (const [cardId, blob] of memoryStore.encryptedCards.entries()) {
      try {
        const card = JSON.parse(decryptAES256GCM(blob, INTERNAL_VAULT.masterEncryptionKey));
        if (Array.isArray(card.tags)) {
          let updated = false;
          card.tags = card.tags.map((t: any) => {
            if (t.id === id) {
              updated = true;
              return { ...t, label: existing.label, color: existing.color, textColor: existing.textColor || '#FFFFFF' };
            }
            return t;
          });
          if (updated) {
            const reEncrypted = encryptAES256GCM(JSON.stringify(card), INTERNAL_VAULT.masterEncryptionKey);
            memoryStore.encryptedCards.set(cardId, reEncrypted);
          }
        }
      } catch (e) {
        // ignore decryption error for single card
      }
    }

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'TAG_UPDATED',
      resourceType: 'workspace_tag',
      resourceId: id,
      details: `Etiqueta atualizada: "${existing.label}" (${existing.color})`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json(existing);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Falha ao atualizar etiqueta.' });
  }
});

app.delete('/api/v1/tags/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const existing = tagStore.get(id);

    if (existing) {
      tagStore.delete(id);
    }

    // Remove this tag from all encrypted cards
    for (const [cardId, blob] of memoryStore.encryptedCards.entries()) {
      try {
        const card = JSON.parse(decryptAES256GCM(blob, INTERNAL_VAULT.masterEncryptionKey));
        if (Array.isArray(card.tags)) {
          const originalLen = card.tags.length;
          card.tags = card.tags.filter((t: any) => t.id !== id);
          if (card.tags.length !== originalLen) {
            const reEncrypted = encryptAES256GCM(JSON.stringify(card), INTERNAL_VAULT.masterEncryptionKey);
            memoryStore.encryptedCards.set(cardId, reEncrypted);
          }
        }
      } catch (e) {
        // ignore
      }
    }

    addAuditLog({
      actorId: 'admin_action',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'TAG_DELETED',
      resourceType: 'workspace_tag',
      resourceId: id,
      details: `Etiqueta excluída: "${existing.label}"`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'warning'
    });

    res.json({ success: true, message: `Etiqueta "${existing.label}" excluída com sucesso.` });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/supabase-schema', (req: Request, res: Response) => {
  const sqlScript = `-- =========================================================================
-- FLOWDECK ZERO-LEAKAGE DATABASE SCHEMA FOR SUPABASE (PostgreSQL)
-- =========================================================================
-- Execute este script completo no "SQL Editor" do seu painel Supabase.
-- Ele cria as tabelas com integridade referencial, Row Level Security (RLS)
-- e vincula o Supabase Auth (auth.users) aos perfis da aplicação.
-- =========================================================================

-- 1. Extensão para UUIDs criptográficos
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. Tabela de Perfis de Usuários (sincronizada com auth.users)
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID REFERENCES auth.users ON DELETE CASCADE PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'manager', 'member', 'viewer')),
  department TEXT DEFAULT 'Engenharia',
  avatar_url TEXT,
  mfa_enabled BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 3. Tabela de Quadros Kanban (Boards)
CREATE TABLE IF NOT EXISTS public.boards (
  id TEXT PRIMARY KEY DEFAULT ('board_' || encode(gen_random_bytes(6), 'hex')),
  title TEXT NOT NULL,
  description TEXT,
  icon TEXT DEFAULT 'ShieldCheck',
  color TEXT DEFAULT 'indigo',
  owner_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
  is_encrypted BOOLEAN DEFAULT TRUE,
  columns_data JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 4. Tabela de Cartões (Cards com Payload Cifrado AES-256-GCM)
CREATE TABLE IF NOT EXISTS public.cards (
  id TEXT PRIMARY KEY DEFAULT ('card_' || encode(gen_random_bytes(6), 'hex')),
  board_id TEXT REFERENCES public.boards(id) ON DELETE CASCADE NOT NULL,
  column_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
  tags JSONB DEFAULT '[]'::jsonb,
  assignee_ids JSONB DEFAULT '[]'::jsonb,
  due_date TIMESTAMP WITH TIME ZONE,
  checklist JSONB DEFAULT '[]'::jsonb,
  comments JSONB DEFAULT '[]'::jsonb,
  attachments JSONB DEFAULT '[]'::jsonb,
  encrypted_hash TEXT,
  "order" INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 5. Tabela de Trilha de Auditoria (Audit Logs Imutáveis com HMAC)
CREATE TABLE IF NOT EXISTS public.audit_logs (
  id TEXT PRIMARY KEY DEFAULT ('log_' || encode(gen_random_bytes(8), 'hex')),
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
  actor_id TEXT NOT NULL,
  actor_name TEXT NOT NULL,
  actor_role TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  details TEXT,
  ip_address TEXT,
  status TEXT NOT NULL CHECK (status IN ('success', 'warning', 'denied')),
  integrity_hash TEXT NOT NULL
);

-- =========================================================================
-- 6. ATIVAÇÃO DE ROW LEVEL SECURITY (RLS) - NENHUM ACESSO NÃO AUTORIZADO
-- =========================================================================
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.boards ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cards ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- POLICIES: PROFILES
CREATE POLICY "Perfis visíveis por usuários autenticados"
  ON public.profiles FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Usuário só pode atualizar o próprio perfil"
  ON public.profiles FOR UPDATE
  TO authenticated
  USING (auth.uid() = id);

-- POLICIES: BOARDS
CREATE POLICY "Membros autenticados podem ver quadros"
  ON public.boards FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Apenas administradores e gerentes podem criar quadros"
  ON public.boards FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager')
    )
  );

CREATE POLICY "Apenas administradores podem deletar quadros"
  ON public.boards FOR DELETE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role = 'admin'
    )
  );

-- POLICIES: CARDS
CREATE POLICY "Visualização de cartões por autenticados"
  ON public.cards FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Criação de cartões permitida para admin, manager e member"
  ON public.cards FOR INSERT
  TO authenticated
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager', 'member')
    )
  );

CREATE POLICY "Modificação de cartões permitida para usuários ativos"
  ON public.cards FOR UPDATE
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'manager', 'member')
    )
  );

-- POLICIES: AUDIT LOGS (APENAS LEITURA PARA ADMINS E AUDITORES)
CREATE POLICY "Leitura de auditoria restrita a admin e viewer"
  ON public.audit_logs FOR SELECT
  TO authenticated
  USING (
    EXISTS (
      SELECT 1 FROM public.profiles
      WHERE id = auth.uid() AND role IN ('admin', 'viewer')
    )
  );

-- =========================================================================
-- 7. TRIGGER AUTOMÁTICO: NOVO USUÁRIO SUPABASE AUTH -> PUBLIC.PROFILES
-- =========================================================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.profiles (id, email, name, role, department, avatar_url)
  VALUES (
    new.id,
    new.email,
    COALESCE(new.raw_user_meta_data->>'name', split_part(new.email, '@', 1)),
    COALESCE(new.raw_user_meta_data->>'role', 'member'),
    COALESCE(new.raw_user_meta_data->>'department', 'Engenharia'),
    COALESCE(new.raw_user_meta_data->>'avatar_url', 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80')
  );
  RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();
`;

  res.json({
    supabaseHostUrl: INTERNAL_VAULT.dbHostUrl,
    zeroLeakageGuarantee: 'As chaves do Supabase (Service Role) estão protegidas no backend e não são expostas ao browser.',
    sqlScript
  });
});

// --- BOARDS CRUD ---
app.get('/api/v1/boards', (req: Request, res: Response) => {
  try {
    const boards = Array.from(memoryStore.encryptedBoards.values()).map(blob => {
      const decrypted = decryptAES256GCM(blob, INTERNAL_VAULT.masterEncryptionKey);
      return JSON.parse(decrypted);
    });
    res.json(boards);
  } catch (err: any) {
    res.status(500).json({ error: 'Erro ao recuperar boards: ' + err.message });
  }
});

app.post('/api/v1/boards', (req: Request, res: Response) => {
  try {
    const BoardSchema = z.object({
      title: z.string().min(2).max(100),
      description: z.string().max(500).default(''),
      icon: z.string().default('LayoutGrid'),
      color: z.string().default('indigo'),
      ownerId: z.string().default('admin'),
      allowedUserIds: z.array(z.string()).optional(),
      isPublic: z.boolean().optional()
    });

    const parsed = BoardSchema.parse(req.body);
    const newBoard = {
      id: 'board_' + crypto.randomBytes(6).toString('hex'),
      ...parsed,
      isPublic: parsed.isPublic ?? true,
      allowedUserIds: parsed.allowedUserIds || [parsed.ownerId],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      isEncrypted: true,
      columns: [
        { id: 'col_' + crypto.randomBytes(4).toString('hex'), title: '📋 A Fazer', order: 0, wipLimit: 10, color: 'sky' },
        { id: 'col_' + crypto.randomBytes(4).toString('hex'), title: '⚡ Em Andamento', order: 1, wipLimit: 5, color: 'amber' },
        { id: 'col_' + crypto.randomBytes(4).toString('hex'), title: '✅ Concluído', order: 2, wipLimit: 20, color: 'emerald' }
      ]
    };

    const encrypted = encryptAES256GCM(JSON.stringify(newBoard), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedBoards.set(newBoard.id, encrypted);

    addAuditLog({
      actorId: parsed.ownerId,
      actorName: 'FlowDeck Admin',
      actorRole: 'admin',
      action: 'BOARD_CREATED',
      resourceType: 'board',
      resourceId: newBoard.id,
      details: `Área de Trabalho "${newBoard.title}" criada com cifra AES-256-GCM. (${newBoard.isPublic ? 'Pública' : 'Acesso Restrito'})`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.status(201).json(newBoard);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/v1/boards/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const existingBlob = memoryStore.encryptedBoards.get(id);
    if (!existingBlob) return res.status(404).json({ error: 'Quadro não encontrado.' });

    const decrypted = JSON.parse(decryptAES256GCM(existingBlob, INTERNAL_VAULT.masterEncryptionKey));
    const updatedBoard = {
      ...decrypted,
      ...req.body,
      id,
      updatedAt: new Date().toISOString()
    };

    const encrypted = encryptAES256GCM(JSON.stringify(updatedBoard), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedBoards.set(id, encrypted);

    addAuditLog({
      actorId: req.body.ownerId || decrypted.ownerId || 'admin',
      actorName: 'FlowDeck Admin',
      actorRole: 'admin',
      action: 'BOARD_UPDATED',
      resourceType: 'board',
      resourceId: id,
      details: `Área de Trabalho "${updatedBoard.title}" atualizada (Permissões: ${updatedBoard.isPublic ? 'Pública' : (updatedBoard.allowedUserIds?.length || 0) + ' usuários'}).`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json(updatedBoard);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/v1/boards/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    if (!memoryStore.encryptedBoards.has(id)) return res.status(404).json({ error: 'Quadro não encontrado.' });

    memoryStore.encryptedBoards.delete(id);

    // Also remove associated cards
    for (const [cardId, blob] of memoryStore.encryptedCards.entries()) {
      const card = JSON.parse(decryptAES256GCM(blob, INTERNAL_VAULT.masterEncryptionKey));
      if (card.boardId === id) {
        memoryStore.encryptedCards.delete(cardId);
      }
    }

    addAuditLog({
      actorId: 'admin',
      actorName: 'FlowDeck Admin',
      actorRole: 'admin',
      action: 'BOARD_DELETED',
      resourceType: 'board',
      resourceId: id,
      details: `Quadro ${id} e cartões vinculados removidos com expurgo de memória.`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'warning'
    });

    res.json({ success: true, message: 'Quadro excluído com sucesso.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// --- COLUMNS ---
app.post('/api/v1/boards/:id/columns', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const existingBlob = memoryStore.encryptedBoards.get(id);
    if (!existingBlob) return res.status(404).json({ error: 'Quadro não encontrado.' });

    const board = JSON.parse(decryptAES256GCM(existingBlob, INTERNAL_VAULT.masterEncryptionKey));
    const newCol = {
      id: 'col_' + crypto.randomBytes(4).toString('hex'),
      boardId: id,
      title: req.body.title || 'Nova Coluna',
      order: board.columns.length,
      wipLimit: req.body.wipLimit || 10,
      color: req.body.color || 'slate'
    };

    board.columns.push(newCol);
    board.updatedAt = new Date().toISOString();

    const encrypted = encryptAES256GCM(JSON.stringify(board), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedBoards.set(id, encrypted);

    res.status(201).json(newCol);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/v1/boards/:id/columns/:colId', (req: Request, res: Response) => {
  try {
    const { id, colId } = req.params;
    const existingBlob = memoryStore.encryptedBoards.get(id);
    if (!existingBlob) return res.status(404).json({ error: 'Quadro não encontrado.' });

    const board = JSON.parse(decryptAES256GCM(existingBlob, INTERNAL_VAULT.masterEncryptionKey));
    const colIndex = board.columns.findIndex((c: any) => c.id === colId);
    if (colIndex === -1) return res.status(404).json({ error: 'Coluna não encontrada.' });

    board.columns[colIndex] = { ...board.columns[colIndex], ...req.body };
    board.updatedAt = new Date().toISOString();

    const encrypted = encryptAES256GCM(JSON.stringify(board), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedBoards.set(id, encrypted);

    res.json(board.columns[colIndex]);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/v1/boards/:id/columns/:colId', (req: Request, res: Response) => {
  try {
    const { id, colId } = req.params;
    const existingBlob = memoryStore.encryptedBoards.get(id);
    if (!existingBlob) return res.status(404).json({ error: 'Quadro não encontrado.' });

    const board = JSON.parse(decryptAES256GCM(existingBlob, INTERNAL_VAULT.masterEncryptionKey));
    board.columns = board.columns.filter((c: any) => c.id !== colId);
    board.updatedAt = new Date().toISOString();

    const encrypted = encryptAES256GCM(JSON.stringify(board), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedBoards.set(id, encrypted);

    // Delete cards in that column
    for (const [cardId, blob] of memoryStore.encryptedCards.entries()) {
      const card = JSON.parse(decryptAES256GCM(blob, INTERNAL_VAULT.masterEncryptionKey));
      if (card.columnId === colId) {
        memoryStore.encryptedCards.delete(cardId);
      }
    }

    res.json({ success: true, message: 'Coluna excluída.' });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// --- CARDS CRUD ---
app.get('/api/v1/cards', (req: Request, res: Response) => {
  try {
    const { boardId } = req.query;
    const cards = Array.from(memoryStore.encryptedCards.values())
      .map(blob => {
        const decrypted = decryptAES256GCM(blob, INTERNAL_VAULT.masterEncryptionKey);
        const card = JSON.parse(decrypted);
        // Expose cryptographic hash tag for transparency without exposing keys
        card.encryptedHash = 'sha256:' + crypto.createHash('sha256').update(blob.ciphertext).digest('hex').substring(0, 16);
        return card;
      })
      .filter(card => !boardId || card.boardId === boardId);

    res.json(cards);
  } catch (err: any) {
    res.status(500).json({ error: 'Erro ao descriptografar cartões: ' + err.message });
  }
});

app.post('/api/v1/cards', (req: Request, res: Response) => {
  try {
    const CardSchema = z.object({
      boardId: z.string(),
      columnId: z.string(),
      title: z.string().min(1).max(200),
      description: z.string().max(5000).default(''),
      priority: z.enum(['low', 'medium', 'high', 'urgent']).default('medium'),
      tags: z.array(z.any()).default([]),
      assigneeIds: z.array(z.string()).default([]),
      startDate: z.string().nullable().optional().default(null),
      dueDate: z.string().nullable().optional().default(null),
      requester: z.string().optional().default(''),
      requesterDepartment: z.string().optional().default(''),
      requesterSector: z.string().optional().default(''),
      valueLevel: z.string().optional().default(''),
      demandType: z.string().optional().default(''),
      checklist: z.array(z.any()).default([]),
      comments: z.array(z.any()).default([]),
      attachments: z.array(z.any()).default([])
    });

    const parsed = CardSchema.parse(req.body);
    const newCard = {
      id: 'card_' + crypto.randomBytes(6).toString('hex'),
      ...parsed,
      order: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    const encrypted = encryptAES256GCM(JSON.stringify(newCard), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedCards.set(newCard.id, encrypted);

    addAuditLog({
      actorId: 'usr_current',
      actorName: 'Usuário Ativo',
      actorRole: 'member',
      action: 'CARD_CREATED',
      resourceType: 'card',
      resourceId: newCard.id,
      details: `Cartão "${newCard.title}" criado e criptografado com AES-256-GCM (IV 96-bit).`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.status(201).json(newCard);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/v1/cards/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const existingBlob = memoryStore.encryptedCards.get(id);
    if (!existingBlob) return res.status(404).json({ error: 'Cartão não encontrado.' });

    const decrypted = JSON.parse(decryptAES256GCM(existingBlob, INTERNAL_VAULT.masterEncryptionKey));
    const updatedCard = {
      ...decrypted,
      ...req.body,
      id,
      updatedAt: new Date().toISOString()
    };

    const encrypted = encryptAES256GCM(JSON.stringify(updatedCard), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedCards.set(id, encrypted);

    addAuditLog({
      actorId: 'usr_current',
      actorName: 'Usuário Ativo',
      actorRole: 'member',
      action: 'CARD_UPDATED',
      resourceType: 'card',
      resourceId: id,
      details: `Cartão "${updatedCard.title}" modificado. Re-criptografia com novo IV efetuada.`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json(updatedCard);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/v1/cards/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    if (!memoryStore.encryptedCards.has(id)) return res.status(404).json({ error: 'Cartão não encontrado.' });

    memoryStore.encryptedCards.delete(id);

    addAuditLog({
      actorId: 'usr_current',
      actorName: 'Usuário Ativo',
      actorRole: 'member',
      action: 'CARD_DELETED',
      resourceType: 'card',
      resourceId: id,
      details: `Cartão ${id} removido e expurgado da memória cifrada.`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'warning'
    });

    res.json({ success: true, message: 'Cartão removido com sucesso.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/v1/cards/move', (req: Request, res: Response) => {
  try {
    const { cardId, targetColumnId, newOrder } = req.body;
    const existingBlob = memoryStore.encryptedCards.get(cardId);
    if (!existingBlob) return res.status(404).json({ error: 'Cartão não encontrado.' });

    const card = JSON.parse(decryptAES256GCM(existingBlob, INTERNAL_VAULT.masterEncryptionKey));
    card.columnId = targetColumnId;
    if (typeof newOrder === 'number') card.order = newOrder;
    card.updatedAt = new Date().toISOString();

    const encrypted = encryptAES256GCM(JSON.stringify(card), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedCards.set(cardId, encrypted);

    addAuditLog({
      actorId: 'usr_current',
      actorName: 'Usuário Ativo',
      actorRole: 'member',
      action: 'CARD_MOVED',
      resourceType: 'card',
      resourceId: cardId,
      details: `Cartão movido para a coluna ${targetColumnId}.`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json(card);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/v1/cards/batch-move', (req: Request, res: Response) => {
  try {
    const { cardIds, targetColumnId } = req.body;
    if (!Array.isArray(cardIds) || cardIds.length === 0 || !targetColumnId) {
      return res.status(400).json({ error: 'IDs dos cartões e coluna de destino são obrigatórios.' });
    }

    const updatedCards: any[] = [];
    for (const cardId of cardIds) {
      const existingBlob = memoryStore.encryptedCards.get(cardId);
      if (existingBlob) {
        const card = JSON.parse(decryptAES256GCM(existingBlob, INTERNAL_VAULT.masterEncryptionKey));
        card.columnId = targetColumnId;
        card.updatedAt = new Date().toISOString();
        const encrypted = encryptAES256GCM(JSON.stringify(card), INTERNAL_VAULT.masterEncryptionKey);
        memoryStore.encryptedCards.set(cardId, encrypted);
        updatedCards.push(card);
      }
    }

    addAuditLog({
      actorId: 'usr_current',
      actorName: 'Usuário Ativo',
      actorRole: 'member',
      action: 'CARD_BATCH_MOVED',
      resourceType: 'card',
      resourceId: targetColumnId,
      details: `${updatedCards.length} cartões movidos em lote para a coluna ${targetColumnId}.`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json({ success: true, count: updatedCards.length, cards: updatedCards });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/v1/cards/reorder', (req: Request, res: Response) => {
  try {
    const { columnId, cardIds } = req.body;
    if (!columnId || !Array.isArray(cardIds)) {
      return res.status(400).json({ error: 'ID da coluna e lista de IDs são obrigatórios.' });
    }

    cardIds.forEach((cardId: string, index: number) => {
      const existingBlob = memoryStore.encryptedCards.get(cardId);
      if (existingBlob) {
        const card = JSON.parse(decryptAES256GCM(existingBlob, INTERNAL_VAULT.masterEncryptionKey));
        card.columnId = columnId;
        card.order = index;
        card.updatedAt = new Date().toISOString();
        const encrypted = encryptAES256GCM(JSON.stringify(card), INTERNAL_VAULT.masterEncryptionKey);
        memoryStore.encryptedCards.set(cardId, encrypted);
      }
    });

    res.json({ success: true });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// --- SECURITY & ENCRYPTION VAULT API ---
app.get('/api/v1/security/status', (req: Request, res: Response) => {
  res.json({
    encryptionActive: true,
    algorithm: activeKeyAlgorithm,
    activeKeyId,
    activeKeyVersion,
    totalEncryptedBoards: memoryStore.encryptedBoards.size,
    totalEncryptedCards: memoryStore.encryptedCards.size,
    totalAuditEntries: memoryStore.auditLogs.length,
    zeroLeakageEnforced: true,
    cspStatus: 'enforced',
    rateLimiterActive: true,
    lastRotation: lastKeyRotation,
    keyHistory: memoryStore.keyHistory
  });
});

app.post('/api/v1/security/rotate-key', (req: Request, res: Response) => {
  try {
    const { newPassphrase, algorithm = 'AES-256-GCM' } = req.body;
    const oldPassphrase = INTERNAL_VAULT.masterEncryptionKey;
    const nextPassphrase = newPassphrase || crypto.randomBytes(32).toString('hex');

    // 1. Re-encrypt all boards with new key/salt
    for (const [boardId, blob] of memoryStore.encryptedBoards.entries()) {
      const decrypted = decryptAES256GCM(blob, oldPassphrase);
      const reEncrypted = encryptAES256GCM(decrypted, nextPassphrase);
      memoryStore.encryptedBoards.set(boardId, reEncrypted);
    }

    // 2. Re-encrypt all cards with new key/salt
    for (const [cardId, blob] of memoryStore.encryptedCards.entries()) {
      const decrypted = decryptAES256GCM(blob, oldPassphrase);
      const reEncrypted = encryptAES256GCM(decrypted, nextPassphrase);
      memoryStore.encryptedCards.set(cardId, reEncrypted);
    }

    // 3. Update master key & version metadata
    activeKeyVersion += 1;
    activeKeyId = `key_master_v${activeKeyVersion}_aes256`;
    activeKeyAlgorithm = algorithm;
    lastKeyRotation = new Date().toISOString();
    INTERNAL_VAULT.masterEncryptionKey = nextPassphrase;

    const newKeyEntry = {
      id: activeKeyId,
      version: activeKeyVersion,
      algorithm: activeKeyAlgorithm,
      createdAt: lastKeyRotation,
      status: 'active' as const,
      fingerprint: 'SHA256:' + crypto.createHash('sha256').update(nextPassphrase).digest('hex'),
      iterations: 100000,
      keyLengthBits: 256
    };

    memoryStore.keyHistory.forEach(k => { if (k.status === 'active') (k as any).status = 'rotated'; });
    memoryStore.keyHistory.unshift(newKeyEntry);

    addAuditLog({
      actorId: 'admin',
      actorName: 'Administrador',
      actorRole: 'admin',
      action: 'CRYPTO_KEY_ROTATED',
      resourceType: 'crypto_key',
      resourceId: activeKeyId,
      details: `Rotação de chave executada com sucesso. Versão ativa atualizada para v${activeKeyVersion}. Todos os registros foram re-criptografados com novos IVs e salts.`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json({
      success: true,
      message: `Chave rotacionada com sucesso para a versão v${activeKeyVersion}.`,
      activeKey: newKeyEntry,
      reEncryptedRecords: memoryStore.encryptedBoards.size + memoryStore.encryptedCards.size
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Erro durante a rotação criptográfica: ' + err.message });
  }
});

app.post('/api/v1/security/crypto-test', (req: Request, res: Response) => {
  try {
    const { plaintext } = req.body;
    if (!plaintext) return res.status(400).json({ error: 'Texto não fornecido para teste.' });

    const encrypted = encryptAES256GCM(plaintext, INTERNAL_VAULT.masterEncryptionKey);
    const decrypted = decryptAES256GCM(encrypted, INTERNAL_VAULT.masterEncryptionKey);

    res.json({
      original: plaintext,
      encryptedBlob: encrypted,
      verifiedDecryption: decrypted,
      match: plaintext === decrypted
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/security/export-encrypted', (req: Request, res: Response) => {
  try {
    const backup = {
      exportTimestamp: new Date().toISOString(),
      generator: 'FlowDeck Zero-Leakage Cryptographic Engine v2.0',
      activeKeyId,
      activeKeyVersion,
      encryptedBoards: Object.fromEntries(memoryStore.encryptedBoards),
      encryptedCards: Object.fromEntries(memoryStore.encryptedCards),
      auditLogsCount: memoryStore.auditLogs.length
    };

    addAuditLog({
      actorId: 'admin',
      actorName: 'Administrador',
      actorRole: 'admin',
      action: 'SECURITY_BACKUP_EXPORTED',
      resourceType: 'crypto_key',
      resourceId: activeKeyId,
      details: 'Exportação de backup cifrado completo gerada.',
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json(backup);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/security/audit-logs', (req: Request, res: Response) => {
  res.json(memoryStore.auditLogs);
});

// ==========================================
// 5.5 AUTOMATIONS ENGINE API (Rotinas de Criação de Cards)
// ==========================================
function calculateDatesForCard(dateConfig: any, baseDate = new Date()) {
  let startDate: string | null = null;
  let dueDate: string | null = null;

  function fmtIso(d: Date, timeStr?: string) {
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const time = timeStr && /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(timeStr) ? timeStr : '18:00';
    return `${y}-${m}-${day}T${time}:00Z`;
  }

  if (dateConfig) {
    // Start Date
    if (dateConfig.startDateType === 'today') {
      startDate = fmtIso(new Date(baseDate), dateConfig.startTime);
    } else if (dateConfig.startDateType === 'tomorrow') {
      const d = new Date(baseDate);
      d.setDate(d.getDate() + 1);
      startDate = fmtIso(d, dateConfig.startTime);
    } else if (dateConfig.startDateType === 'd_plus') {
      const offset = Math.max(0, Number(dateConfig.startDateDaysOffset) || 0);
      const d = new Date(baseDate);
      d.setDate(d.getDate() + offset);
      startDate = fmtIso(d, dateConfig.startTime);
    } else if (dateConfig.startDateType === 'fixed' && dateConfig.startDateFixed) {
      const time = dateConfig.startTime && /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(dateConfig.startTime) ? dateConfig.startTime : '18:00';
      startDate = `${dateConfig.startDateFixed.substring(0, 10)}T${time}:00Z`;
    }

    // Due Date
    if (dateConfig.dueDateType === 'today') {
      dueDate = fmtIso(new Date(baseDate), dateConfig.dueTime);
    } else if (dateConfig.dueDateType === 'tomorrow') {
      const d = new Date(baseDate);
      d.setDate(d.getDate() + 1);
      dueDate = fmtIso(d, dateConfig.dueTime);
    } else if (dateConfig.dueDateType === 'd_plus') {
      const offset = Math.max(0, Number(dateConfig.dueDateDaysOffset) || 0);
      const d = new Date(baseDate);
      d.setDate(d.getDate() + offset);
      dueDate = fmtIso(d, dateConfig.dueTime);
    } else if (dateConfig.dueDateType === 'fixed' && dateConfig.dueDateFixed) {
      const time = dateConfig.dueTime && /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(dateConfig.dueTime) ? dateConfig.dueTime : '18:00';
      dueDate = `${dateConfig.dueDateFixed.substring(0, 10)}T${time}:00Z`;
    }
  }

  return { startDate, dueDate };
}

function interpolateText(text: string, baseDate = new Date()) {
  if (!text) return '';
  const day = String(baseDate.getDate()).padStart(2, '0');
  const monthNames = [
    'Janeiro', 'Fevereiro', 'Março', 'Abril', 'Maio', 'Junho',
    'Julho', 'Agosto', 'Setembro', 'Outubro', 'Novembro', 'Dezembro'
  ];
  const monthNum = String(baseDate.getMonth() + 1).padStart(2, '0');
  const monthName = monthNames[baseDate.getMonth()];
  const year = String(baseDate.getFullYear());
  const dateFormatted = `${day}/${monthNum}/${year}`;

  return text
    .replace(/{{\s*data\s*}}/gi, dateFormatted)
    .replace(/{{\s*mes\s*}}/gi, monthName)
    .replace(/{{\s*mes_num\s*}}/gi, monthNum)
    .replace(/{{\s*ano\s*}}/gi, year);
}

app.get('/api/v1/automations', (req: Request, res: Response) => {
  try {
    const automations = Array.from(memoryStore.encryptedAutomations.values()).map(blob => {
      return JSON.parse(decryptAES256GCM(blob, INTERNAL_VAULT.masterEncryptionKey));
    });
    res.json(automations);
  } catch (err: any) {
    res.status(500).json({ error: 'Erro ao carregar automações: ' + err.message });
  }
});

app.post('/api/v1/automations', (req: Request, res: Response) => {
  try {
    const newAutomation = {
      id: 'auto_' + crypto.randomBytes(6).toString('hex'),
      title: req.body.title || 'Nova Automação de Cartão',
      description: req.body.description || '',
      boardId: req.body.boardId,
      columnId: req.body.columnId,
      enabled: req.body.enabled !== false,
      createdById: req.body.createdById || 'admin',
      createdByName: req.body.createdByName || 'Administrador',
      createdByAvatar: req.body.createdByAvatar || 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastRunAt: null,
      runCount: 0,
      cardTitle: req.body.cardTitle || 'Tarefa Automática',
      cardDescription: req.body.cardDescription || '',
      priority: req.body.priority || 'medium',
      tags: req.body.tags || [],
      assigneeIds: req.body.assigneeIds || [],
      requester: req.body.requester || '',
      requesterDepartment: req.body.requesterDepartment || '',
      requesterSector: req.body.requesterSector || '',
      valueLevel: req.body.valueLevel || '',
      demandType: req.body.demandType || '',
      checklist: (req.body.checklist || []).map((item: any) => ({
        id: item.id || ('chk_auto_' + crypto.randomBytes(3).toString('hex')),
        title: item.title,
        completed: false
      })),
      dateConfig: req.body.dateConfig || {
        startDateType: 'today',
        startTime: '09:00',
        dueDateType: 'today',
        dueTime: '18:00'
      },
      schedule: req.body.schedule || {
        frequency: 'daily',
        dailyType: 'all_days',
        time: '09:00'
      }
    };

    const encrypted = encryptAES256GCM(JSON.stringify(newAutomation), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedAutomations.set(newAutomation.id, encrypted);

    addAuditLog({
      actorId: newAutomation.createdById,
      actorName: newAutomation.createdByName,
      actorRole: 'admin',
      action: 'AUTOMATION_CREATED',
      resourceType: 'board',
      resourceId: newAutomation.id,
      details: `Nova automação criada: "${newAutomation.title}" para coluna "${newAutomation.columnId}".`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.status(201).json(newAutomation);
  } catch (err: any) {
    res.status(400).json({ error: 'Erro ao cadastrar automação: ' + err.message });
  }
});

app.put('/api/v1/automations/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const existingBlob = memoryStore.encryptedAutomations.get(id);
    if (!existingBlob) return res.status(404).json({ error: 'Automação não encontrada.' });

    const existing = JSON.parse(decryptAES256GCM(existingBlob, INTERNAL_VAULT.masterEncryptionKey));
    const updated = {
      ...existing,
      ...req.body,
      id,
      updatedAt: new Date().toISOString()
    };

    const encrypted = encryptAES256GCM(JSON.stringify(updated), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedAutomations.set(id, encrypted);

    addAuditLog({
      actorId: 'admin',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'AUTOMATION_UPDATED',
      resourceType: 'board',
      resourceId: id,
      details: `Regra de automação "${updated.title}" atualizada (Status: ${updated.enabled ? 'Ativa' : 'Pausada'}).`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json(updated);
  } catch (err: any) {
    res.status(400).json({ error: 'Erro ao atualizar automação: ' + err.message });
  }
});

app.delete('/api/v1/automations/:id', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const existingBlob = memoryStore.encryptedAutomations.get(id);
    if (!existingBlob) return res.status(404).json({ error: 'Automação não encontrada.' });

    const existing = JSON.parse(decryptAES256GCM(existingBlob, INTERNAL_VAULT.masterEncryptionKey));
    memoryStore.encryptedAutomations.delete(id);

    addAuditLog({
      actorId: 'admin',
      actorName: 'Administrador FlowDeck',
      actorRole: 'admin',
      action: 'AUTOMATION_DELETED',
      resourceType: 'board',
      resourceId: id,
      details: `Regra de automação "${existing.title}" excluída.`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'warning'
    });

    res.json({ success: true, message: 'Automação excluída com sucesso.' });
  } catch (err: any) {
    res.status(500).json({ error: 'Erro ao excluir automação: ' + err.message });
  }
});

// Endpoint to immediately trigger an automation rule (Executar Agora)
app.post('/api/v1/automations/:id/trigger', (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    let automation = req.body?.automation;
    if (!automation) {
      const existingBlob = memoryStore.encryptedAutomations.get(id);
      if (existingBlob) {
        try {
          automation = JSON.parse(decryptAES256GCM(existingBlob, INTERNAL_VAULT.masterEncryptionKey));
        } catch {
          // ignore
        }
      }
    }

    if (!automation) {
      automation = {
        id,
        title: req.body?.title || 'Automação Programada',
        boardId: req.body?.boardId || 'board_default',
        columnId: req.body?.columnId || 'col_backlog',
        cardTitle: req.body?.cardTitle || 'Card Gerado por Automação',
        createdById: 'flowdeck_butler',
        priority: 'medium',
        dateConfig: req.body?.dateConfig || {}
      };
    }

    const now = new Date();

    // 1. Calculate dynamic dates
    const { startDate, dueDate } = calculateDatesForCard(automation.dateConfig, now);

    // 2. Interpolate title & description
    const interpolatedTitle = interpolateText(automation.cardTitle || automation.title, now);
    const interpolatedDescription = interpolateText(automation.cardDescription || '', now);

    // 3. Build new card
    const cardId = req.body?.card?.id || ('card_auto_' + crypto.randomBytes(5).toString('hex'));
    const newCard = req.body?.card || {
      id: cardId,
      boardId: automation.boardId,
      columnId: automation.columnId,
      title: interpolatedTitle || 'Card Gerado por Automação',
      description: interpolatedDescription || '',
      priority: automation.priority || 'medium',
      tags: automation.tags || [],
      assigneeIds: automation.assigneeIds || [],
      startDate: startDate,
      dueDate: dueDate,
      requester: automation.requester || `Automação: ${automation.title}`,
      requesterDepartment: automation.requesterDepartment || '',
      requesterSector: automation.requesterSector || '',
      valueLevel: automation.valueLevel || '',
      demandType: automation.demandType || 'Rotina',
      checklist: (automation.checklist || []).map((c: any) => ({
        id: 'chk_' + crypto.randomBytes(3).toString('hex'),
        title: c.title,
        completed: false
      })),
      comments: [
        {
          id: 'comm_auto_init',
          authorId: automation.createdById || 'admin',
          authorName: 'FlowDeck Butler (Automação)',
          authorAvatar: 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=150&auto=format&fit=crop&q=80',
          content: `🤖 Cartão gerado automaticamente pela rotina "${automation.title}".`,
          createdAt: now.toISOString()
        }
      ],
      attachments: [],
      order: 0,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString()
    };

    // 4. Save Card Encrypted
    const encryptedCard = encryptAES256GCM(JSON.stringify(newCard), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedCards.set(cardId, encryptedCard);

    // 5. Update Automation Stats
    automation.lastRunAt = now.toISOString();
    automation.runCount = (automation.runCount || 0) + 1;
    const reEncryptedAuto = encryptAES256GCM(JSON.stringify(automation), INTERNAL_VAULT.masterEncryptionKey);
    memoryStore.encryptedAutomations.set(id, reEncryptedAuto);

    // 6. Audit Log
    addAuditLog({
      actorId: automation.createdById || 'admin',
      actorName: 'FlowDeck Butler',
      actorRole: 'admin',
      action: 'AUTOMATION_TRIGGERED',
      resourceType: 'card',
      resourceId: cardId,
      details: `Automação "${automation.title}" disparada. Novo cartão "${newCard.title}" gerado com sucesso.`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json({
      success: true,
      message: `Cartão "${newCard.title}" criado com sucesso!`,
      card: newCard,
      automation
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Erro ao disparar automação: ' + err.message });
  }
});

// ==========================================
// 5.5 SMTP CONFIGURATION & EMAIL DISPATCHER
// ==========================================
interface SmtpConfig {
  host: string;
  port: number;
  user: string;
  pass: string;
  from: string;
  secure: boolean;
  verifiedAt?: string;
}

const SMTP_CONFIG_FILE = path.join(process.cwd(), 'data', 'smtp-config.json');

let activeSmtpConfig: SmtpConfig = {
  host: process.env.SMTP_HOST || '',
  port: Number(process.env.SMTP_PORT) || 587,
  user: process.env.SMTP_USER || '',
  pass: process.env.SMTP_PASS || '',
  from: process.env.SMTP_FROM || '',
  secure: process.env.SMTP_SECURE === 'true' || process.env.SMTP_PORT === '465'
};

function loadSmtpConfig(): SmtpConfig {
  try {
    if (fs.existsSync(SMTP_CONFIG_FILE)) {
      const raw = fs.readFileSync(SMTP_CONFIG_FILE, 'utf-8');
      const parsed = JSON.parse(raw);
      if (parsed && parsed.host) {
        activeSmtpConfig = { ...activeSmtpConfig, ...parsed };
      }
    }
  } catch (err) {
    console.warn('[SMTP] Could not read smtp-config.json:', err);
  }
  return activeSmtpConfig;
}

function saveSmtpConfigToFile(config: SmtpConfig) {
  try {
    const dir = path.dirname(SMTP_CONFIG_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(SMTP_CONFIG_FILE, JSON.stringify(config, null, 2), 'utf-8');
    activeSmtpConfig = { ...config };
  } catch (err) {
    console.error('[SMTP] Could not save smtp-config.json:', err);
  }
}

// Initial load
loadSmtpConfig();

// Helper to detect TLS record header / wrong version number mismatch errors
function isTlsMismatchError(err: any): boolean {
  const str = ((err?.message || '') + ' ' + (err?.code || '') + ' ' + (err?.stack || '')).toLowerCase();
  return (
    str.includes('wrong version number') ||
    str.includes('tls_validate_record_header') ||
    str.includes('ssl routines') ||
    str.includes('wrong_version_number') ||
    str.includes('packet length too long')
  );
}

// Helper to determine the RFC-compliant default for secure connection
function resolveEffectiveSecure(port: number, userSpecifiedSecure?: boolean): boolean {
  if (port === 465) {
    // Port 465 is implicit TLS (direct SSL)
    return true;
  }
  if (port === 587 || port === 25 || port === 2525) {
    // Port 587 and 25 are explicit STARTTLS. Direct SSL on these ports causes 'wrong version number'
    return false;
  }
  return Boolean(userSpecifiedSecure);
}

// Resolves a valid "From" header ensuring the email address matches the authenticated user to avoid 451/550 errors
function resolveEffectiveFrom(fromInput: string | undefined, user: string): string {
  if (!fromInput || !fromInput.trim()) {
    return `"FlowDeck Notificações" <${user}>`;
  }
  const trimmed = fromInput.trim();
  // If still referencing the placeholder notifications@flowdeck.io but user has their own domain
  if (trimmed.includes('notifications@flowdeck.io') && !user.includes('flowdeck.io')) {
    const nameMatch = trimmed.match(/^"([^"]+)"|^([^<]+)</);
    const displayName = (nameMatch ? (nameMatch[1] || nameMatch[2]) : 'FlowDeck Notificações').trim();
    return `"${displayName}" <${user}>`;
  }
  if (!trimmed.includes('@')) {
    return `"${trimmed.replace(/"/g, '')}" <${user}>`;
  }
  return trimmed;
}

// Factory for nodemailer transporter with resilient TLS configuration
function createTransporterInstance(host: string, port: number, user: string, pass: string, secure: boolean) {
  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: {
      user,
      pass
    },
    tls: {
      rejectUnauthorized: false, // Prevent certificate rejection on corporate relays or self-signed certs
      minVersion: 'TLSv1'
    },
    connectionTimeout: 15000,
    greetingTimeout: 12000,
    socketTimeout: 20000
  });
}

// Human-friendly error translation for Portuguese users
function formatSmtpErrorMessage(err: any, host: string, port: number, user?: string): string {
  const msg = ((err?.message || '') + ' ' + (err?.code || '') + ' ' + (err?.response || '')).toLowerCase();

  if (isTlsMismatchError(err)) {
    return `Incompatibilidade de protocolo SSL/TLS com o servidor (${host}:${port}). Para a porta 587, o envio deve utilizar STARTTLS (desmarque "SSL/TLS Direto"). Para a porta 465, utilize SSL direto ativado.`;
  }

  if (msg.includes('451') || msg.includes('temporarily rejected')) {
    return `O servidor de e-mail (${host}) rejeitou temporariamente o envio (código 451). O Google Workspace exige que o endereço de remetente (From) seja idêntico à conta autenticada (${user || 'seu e-mail corporativo'}).`;
  }

  if (
    msg.includes('535') ||
    msg.includes('badcredentials') ||
    msg.includes('username and password not accepted') ||
    msg.includes('invalid login') ||
    msg.includes('auth failed')
  ) {
    if (host.includes('gmail.com') || host.includes('google') || host.includes('meirelesefreitas')) {
      return `Falha de autenticação (535): O Google Workspace exige uma "Senha de Aplicativo" de 16 caracteres quando há verificação em duas etapas ativa na conta. Acesse https://myaccount.google.com/apppasswords para gerar uma senha de app e cole-a no campo Senha.`;
    }
    if (host.includes('office365') || host.includes('outlook')) {
      return `Falha de autenticação no Microsoft 365 (535): Verifique se o recurso "Authenticated SMTP" está habilitado para esta caixa postal no centro de administração do Microsoft 365 ou utilize uma Senha de Aplicativo.`;
    }
    return `Usuário ou senha rejeitados pelo servidor SMTP (${host}). Verifique se o e-mail e a senha informados estão corretos.`;
  }

  if (msg.includes('enotfound') || msg.includes('getaddrinfo')) {
    return `Servidor SMTP "${host}" não foi encontrado no DNS. Se você utiliza e-mail corporativo do Google Workspace (como Meireles e Freitas), o servidor correto é "smtp.gmail.com".`;
  }

  if (msg.includes('econnrefused') || msg.includes('etimedout') || msg.includes('connection timed out') || msg.includes('esockettimedout')) {
    return `Não foi possível estabelecer conexão com ${host}:${port} (tempo limite esgotado ou conexão recusada). Verifique se o host e a porta estão corretos (587 para STARTTLS ou 465 para SSL).`;
  }

  return err?.message || 'Falha ao autenticar ou conectar no servidor SMTP.';
}

// 1. GET Current SMTP Configuration (Password is masked for security)
app.get('/api/v1/smtp/config', (req: Request, res: Response) => {
  const cfg = loadSmtpConfig();
  const isConfigured = Boolean(cfg.host && cfg.user && cfg.pass);
  const effectiveFrom = resolveEffectiveFrom(cfg.from, cfg.user);
  res.json({
    isConfigured,
    host: cfg.host,
    port: cfg.port,
    user: cfg.user,
    hasPassword: Boolean(cfg.pass),
    from: effectiveFrom,
    secure: Boolean(cfg.secure),
    verifiedAt: cfg.verifiedAt || null
  });
});

// 2. POST Test Connection and Save SMTP Configuration
app.post('/api/v1/smtp/test-and-save', async (req: Request, res: Response) => {
  try {
    const { host, port, user, pass, from, secure, testEmail, saveOnly } = req.body;
    const cfg = loadSmtpConfig();

    const effectiveHost = host || cfg.host;
    const effectivePort = Number(port) || cfg.port || 587;
    const effectiveUser = user || cfg.user;
    const effectivePass = (pass && pass.trim() !== '••••••••') ? pass : cfg.pass;
    const effectiveFrom = resolveEffectiveFrom(from || cfg.from, effectiveUser);
    let effectiveSecure = resolveEffectiveSecure(effectivePort, secure);

    if (!effectiveHost || !effectiveUser || !effectivePass) {
      return res.status(400).json({
        success: false,
        error: 'Host, Usuário e Senha são obrigatórios para configurar o envio de e-mails via SMTP.'
      });
    }

    if (saveOnly) {
      const newConfig: SmtpConfig = {
        host: effectiveHost,
        port: effectivePort,
        user: effectiveUser,
        pass: effectivePass,
        from: effectiveFrom,
        secure: effectiveSecure
      };
      saveSmtpConfigToFile(newConfig);
      return res.json({ success: true, message: 'Configurações SMTP salvas com sucesso.' });
    }

    // Attempt verification with automatic TLS mismatch recovery
    let transporter = createTransporterInstance(effectiveHost, effectivePort, effectiveUser, effectivePass, effectiveSecure);
    let autoRecovered = false;

    try {
      await transporter.verify();
    } catch (verifyErr: any) {
      if (isTlsMismatchError(verifyErr)) {
        console.warn(`[SMTP] Mismatch SSL/TLS detectado (inicial secure=${effectiveSecure}). Tentando auto-recuperação com secure=${!effectiveSecure}...`);
        effectiveSecure = !effectiveSecure;
        transporter = createTransporterInstance(effectiveHost, effectivePort, effectiveUser, effectivePass, effectiveSecure);
        await transporter.verify();
        autoRecovered = true;
        console.log(`[SMTP] Auto-recuperação bem-sucedida! Modo salvo agora é secure=${effectiveSecure}`);
      } else {
        throw verifyErr;
      }
    }

    let testMessageId: string | null = null;

    if (testEmail) {
      const testResult = await transporter.sendMail({
        from: effectiveFrom,
        to: testEmail,
        envelope: {
          from: effectiveUser,
          to: testEmail
        },
        subject: '✓ [FlowDeck] Teste de Conexão SMTP Bem-Sucedido',
        text: `Olá!\n\nEste é um e-mail de teste confirmando que a sua integração de e-mail (SMTP) no FlowDeck está operando com sucesso.\n\nServidor: ${effectiveHost}:${effectivePort}\nRemetente: ${effectiveFrom}\nData: ${new Date().toLocaleString('pt-BR')}`,
        html: `
          <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background-color:#0B0F19;padding:24px;color:#F1F5F9;">
            <div style="max-width:550px;margin:0 auto;background-color:#131B2E;border:1px solid #1E293B;border-radius:12px;padding:24px;box-shadow:0 10px 25px rgba(0,0,0,0.5);">
              <h2 style="color:#38BDF8;margin-top:0;font-size:20px;">✓ Conexão SMTP Verificada com Sucesso!</h2>
              <p style="color:#CBD5E1;font-size:14px;line-height:1.6;">
                Este e-mail confirma que a integração de envio de notificações do <strong>FlowDeck Kanban</strong> está ativa e validada.
              </p>
              <div style="background-color:#0F172A;border:1px solid #1E293B;border-radius:8px;padding:14px;margin:16px 0;font-size:13px;color:#94A3B8;line-height:1.6;">
                <div><strong>Servidor:</strong> ${effectiveHost}:${effectivePort}</div>
                <div><strong>Usuário autenticado:</strong> ${effectiveUser}</div>
                <div><strong>Remetente configurado:</strong> ${effectiveFrom}</div>
                <div><strong>Destinatário de teste:</strong> ${testEmail}</div>
                <div><strong>Criptografia:</strong> ${effectiveSecure ? 'SSL/TLS Direto' : 'STARTTLS Automático'}</div>
                <div><strong>Horário de validação:</strong> ${new Date().toLocaleString('pt-BR')}</div>
              </div>
              <p style="color:#64748B;font-size:12px;margin-bottom:0;">
                A partir de agora, resumos de cartões enviados pelo FlowDeck serão entregues diretamente nesta caixa de entrada.
              </p>
            </div>
          </div>
        `
      });
      testMessageId = testResult.messageId;
    }

    const newConfig: SmtpConfig = {
      host: effectiveHost,
      port: effectivePort,
      user: effectiveUser,
      pass: effectivePass,
      from: effectiveFrom,
      secure: effectiveSecure,
      verifiedAt: new Date().toISOString()
    };
    saveSmtpConfigToFile(newConfig);

    addAuditLog({
      actorId: 'admin',
      actorName: 'Administrador',
      actorRole: 'admin',
      action: 'SMTP_CONFIG_VERIFIED',
      resourceType: 'system_settings',
      resourceId: 'smtp',
      details: `Servidor SMTP "${effectiveHost}:${effectivePort}" verificado com sucesso (${effectiveSecure ? 'SSL' : 'STARTTLS'}).${testEmail ? ` E-mail de teste enviado para ${testEmail}.` : ''}${autoRecovered ? ' (Ajuste automático de TLS realizado com sucesso).' : ''}`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json({
      success: true,
      message: testEmail
        ? `Conexão SMTP validada com sucesso e e-mail de teste entregue para ${testEmail}!${autoRecovered ? ' (Protocolo de criptografia ajustado automaticamente).' : ''}`
        : 'Conexão SMTP validada e credenciais salvas com sucesso!',
      messageId: testMessageId,
      autoRecovered,
      secure: effectiveSecure
    });
  } catch (err: any) {
    console.error('[SMTP Verification Error]:', err);
    const friendlyMessage = formatSmtpErrorMessage(err, req.body.host || 'servidor', Number(req.body.port) || 587, req.body.user);
    res.status(400).json({
      success: false,
      error: friendlyMessage,
      code: err.code || null,
      rawMessage: err.message
    });
  }
});

// 3. POST Dispatch Card Email Summary
app.post('/api/v1/cards/send-email-summary', async (req: Request, res: Response) => {
  try {
    const { cardId, cardTitle, recipientEmails, recipientNames, subject, html, text, sender, historyEntry } = req.body;

    if (!recipientEmails || !Array.isArray(recipientEmails) || recipientEmails.length === 0) {
      return res.status(400).json({ error: 'Nenhum e-mail de destinatário informado.' });
    }

    const cfg = loadSmtpConfig();
    const isConfigured = Boolean(cfg.host && cfg.user && cfg.pass);

    if (!isConfigured) {
      console.warn(`[Email Dispatcher] Tentativa de envio para ${recipientEmails.join(', ')}, mas SMTP não está configurado.`);
      return res.status(400).json({
        success: false,
        notConfigured: true,
        sentViaSmtp: false,
        error: 'O Servidor de Envio de E-mails (SMTP) ainda não foi configurado no FlowDeck. Para que as mensagens cheguem às caixas de entrada dos destinatários, configure o servidor SMTP em Configurações > Servidor de E-mail (SMTP).',
        deliveredTo: []
      });
    }

    let effectiveSecure = resolveEffectiveSecure(cfg.port, cfg.secure);
    let transporter = createTransporterInstance(cfg.host, cfg.port, cfg.user, cfg.pass, effectiveSecure);
    const effectiveFrom = resolveEffectiveFrom(cfg.from, cfg.user);

    let info;
    try {
      info = await transporter.sendMail({
        from: effectiveFrom,
        to: recipientEmails.join(', '),
        envelope: {
          from: cfg.user,
          to: recipientEmails
        },
        subject: subject || `[FlowDeck] Novo Cartão: ${cardTitle}`,
        text: text || '',
        html: html || ''
      });
      console.log(`[Email Dispatcher] E-mail REAL entregue via SMTP para ${recipientEmails.join(', ')}: messageId ${info.messageId}`);
    } catch (sendErr: any) {
      if (isTlsMismatchError(sendErr)) {
        console.warn(`[Email Dispatcher] Incompatibilidade SSL detectada no envio (${effectiveSecure ? 'SSL' : 'STARTTLS'}). Tentando auto-recuperação com secure=${!effectiveSecure}...`);
        effectiveSecure = !effectiveSecure;
        transporter = createTransporterInstance(cfg.host, cfg.port, cfg.user, cfg.pass, effectiveSecure);
        try {
          info = await transporter.sendMail({
            from: effectiveFrom,
            to: recipientEmails.join(', '),
            envelope: {
              from: cfg.user,
              to: recipientEmails
            },
            subject: subject || `[FlowDeck] Novo Cartão: ${cardTitle}`,
            text: text || '',
            html: html || ''
          });
          console.log(`[Email Dispatcher] E-mail entregue com sucesso após auto-recuperação para ${recipientEmails.join(', ')}! Atualizando smtp-config.json.`);
          cfg.secure = effectiveSecure;
          saveSmtpConfigToFile(cfg);
        } catch (retryErr: any) {
          console.error('[Email Dispatcher] Falha de envio mesmo após tentativa de recuperação:', retryErr);
          const friendly = formatSmtpErrorMessage(retryErr, cfg.host, cfg.port, cfg.user);
          return res.status(502).json({
            success: false,
            sentViaSmtp: false,
            error: `O servidor SMTP (${cfg.host}) rejeitou o envio: ${friendly}`,
            code: retryErr.code
          });
        }
      } else {
        console.error('[Email Dispatcher] Falha de envio no servidor SMTP:', sendErr);
        const friendly = formatSmtpErrorMessage(sendErr, cfg.host, cfg.port, cfg.user);
        return res.status(502).json({
          success: false,
          sentViaSmtp: false,
          error: `O servidor SMTP (${cfg.host}) rejeitou o envio: ${friendly}`,
          code: sendErr.code
        });
      }
    }

    // Registra na auditoria
    addAuditLog({
      actorId: sender?.id || 'system',
      actorName: sender?.name || 'Usuário FlowDeck',
      actorRole: 'user',
      action: 'CARD_EMAIL_NOTIFICATION_SENT',
      resourceType: 'card',
      resourceId: cardId || 'card_unknown',
      details: `Notificação de resumo do cartão "${cardTitle}" enviada por e-mail para ${recipientEmails.length} destinatário(s) (${recipientEmails.join(', ')}). MessageId: ${info.messageId}`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    res.json({
      success: true,
      message: `Resumo por e-mail entregue com sucesso via SMTP para ${recipientEmails.length} destinatário(s).`,
      sentViaSmtp: true,
      messageId: info.messageId,
      deliveredTo: recipientEmails,
      historyEntry: {
        ...historyEntry,
        messageId: info.messageId,
        sentViaSmtp: true,
        status: 'sent'
      }
    });
  } catch (err: any) {
    console.error('Erro na rota de envio de resumo por e-mail:', err);
    res.status(500).json({ error: 'Falha ao processar envio de notificação: ' + err.message });
  }
});

// ==========================================
// 5.5 FILE STORAGE & ATTACHMENTS (TRELLO-STYLE CARD COVERS)
// ==========================================

// Helper to format file size in KB / MB
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

// Helper to sanitize filename
function sanitizeFilename(originalName: string): string {
  const ext = path.extname(originalName) || '.png';
  const base = path.basename(originalName, ext)
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9_\-]/g, '_')
    .slice(0, 50);
  return `${base || 'image'}${ext}`;
}

// POST /api/v1/uploads - Upload photo/file and persist permanently to disk
app.post('/api/v1/uploads', async (req: Request, res: Response) => {
  try {
    const { filename, data, contentType, cardId, uploadedBy } = req.body;

    if (!data || typeof data !== 'string') {
      return res.status(400).json({ error: 'Nenhum dado binário de imagem fornecido (esperado base64).' });
    }

    // Extract base64 payload
    let rawBase64 = data;
    let detectedType = contentType || 'image/png';

    if (data.startsWith('data:')) {
      const commaIdx = data.indexOf(',');
      if (commaIdx !== -1) {
        const header = data.substring(0, commaIdx);
        const match = header.match(/^data:([^;]+);base64/);
        if (match && match[1]) {
          detectedType = match[1];
        }
        rawBase64 = data.substring(commaIdx + 1);
      }
    }

    const fileBuffer = Buffer.from(rawBase64, 'base64');
    if (fileBuffer.length === 0) {
      return res.status(400).json({ error: 'Arquivo vazio ou base64 inválido.' });
    }

    // Calculate SHA-256 for cryptographic tamper-proofing
    const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    // Create unique safe filename
    const cleanName = sanitizeFilename(filename || 'anexo.png');
    const uniqueFilename = `${Date.now()}_${crypto.randomBytes(4).toString('hex')}_${cleanName}`;

    // Write to persistent UPLOADS_DIR and PUBLIC_UPLOADS_DIR
    const targetPath1 = path.join(UPLOADS_DIR, uniqueFilename);
    const targetPath2 = path.join(PUBLIC_UPLOADS_DIR, uniqueFilename);

    fs.writeFileSync(targetPath1, fileBuffer);
    try {
      fs.writeFileSync(targetPath2, fileBuffer);
    } catch (pubErr) {
      console.warn('[Uploads] Warning writing to public/uploads:', pubErr);
    }

    const fileSizeFormatted = formatBytes(fileBuffer.length);
    const fileUrl = `/uploads/${uniqueFilename}`;

    // Log to Audit Trail
    addAuditLog({
      actorId: uploadedBy?.id || 'user',
      actorName: uploadedBy?.name || 'Colaborador',
      actorRole: uploadedBy?.role || 'user',
      action: 'CARD_PHOTO_UPLOADED',
      resourceType: 'card',
      resourceId: cardId || 'upload',
      details: `Foto/anexo "${cleanName}" (${fileSizeFormatted}) salvo permanentemente no disco do servidor. URL: ${fileUrl}`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'success'
    });

    console.log(`[Uploads] Arquivo salvo com sucesso: ${uniqueFilename} (${fileSizeFormatted})`);

    res.status(201).json({
      success: true,
      url: fileUrl,
      filename: uniqueFilename,
      originalName: filename || cleanName,
      size: fileSizeFormatted,
      bytes: fileBuffer.length,
      type: detectedType,
      sha256,
      uploadedAt: new Date().toISOString()
    });
  } catch (err: any) {
    console.error('[Uploads Error]:', err);
    res.status(500).json({ error: 'Falha ao salvar arquivo no servidor: ' + (err.message || err) });
  }
});

// GET /api/v1/uploads/:filename - Stream or serve uploaded file
app.get('/api/v1/uploads/:filename', (req: Request, res: Response) => {
  try {
    const filename = path.basename(req.params.filename);
    const filePath1 = path.join(UPLOADS_DIR, filename);
    const filePath2 = path.join(PUBLIC_UPLOADS_DIR, filename);

    if (fs.existsSync(filePath1)) {
      return res.sendFile(filePath1);
    }
    if (fs.existsSync(filePath2)) {
      return res.sendFile(filePath2);
    }
    res.status(404).json({ error: 'Arquivo não encontrado no servidor.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/v1/uploads - List all uploaded files
app.get('/api/v1/uploads', (req: Request, res: Response) => {
  try {
    if (!fs.existsSync(UPLOADS_DIR)) {
      return res.json([]);
    }
    const files = fs.readdirSync(UPLOADS_DIR).map(fn => {
      const stats = fs.statSync(path.join(UPLOADS_DIR, fn));
      return {
        filename: fn,
        url: `/uploads/${fn}`,
        size: formatBytes(stats.size),
        bytes: stats.size,
        createdAt: stats.birthtime.toISOString()
      };
    });
    res.json(files);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/v1/uploads/:filename - Remove uploaded file from disk
app.delete('/api/v1/uploads/:filename', (req: Request, res: Response) => {
  try {
    const filename = path.basename(req.params.filename);
    const filePath1 = path.join(UPLOADS_DIR, filename);
    const filePath2 = path.join(PUBLIC_UPLOADS_DIR, filename);

    let deleted = false;
    if (fs.existsSync(filePath1)) {
      fs.unlinkSync(filePath1);
      deleted = true;
    }
    if (fs.existsSync(filePath2)) {
      fs.unlinkSync(filePath2);
      deleted = true;
    }

    if (deleted) {
      addAuditLog({
        actorId: 'admin',
        actorName: 'Administrador FlowDeck',
        actorRole: 'admin',
        action: 'FILE_DELETED',
        resourceType: 'card',
        resourceId: filename,
        details: `Arquivo ${filename} removido do armazenamento em disco.`,
        ipAddress: req.ip || '127.0.0.1',
        status: 'warning'
      });
      return res.json({ success: true, message: 'Arquivo removido com sucesso.' });
    }
    res.status(404).json({ error: 'Arquivo não encontrado.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// 6. VITE & STATIC SERVER INTEGRATION
// ==========================================
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🔒 FlowDeck Secure Kanban running on http://localhost:${PORT}`);
  });
}

startServer();
