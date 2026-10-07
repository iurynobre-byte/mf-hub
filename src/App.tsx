/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  User,
  Workspace,
  Dashboard,
  UserGroup,
  UserRole,
  AuditLog,
  SupabaseConfig,
  PowerBiAccountConfig,
  PowerBiLicenca,
  Department,
} from './types';
import { supabaseService } from './services/supabaseService';
import { brandingService } from './services/brandingService';
import { LoginScreen } from './components/LoginScreen';
import { Header } from './components/Header';
import { PowerBiViewer } from './components/PowerBiViewer';
import { AdminPanel } from './components/AdminPanel';
import { DashboardModal } from './components/modals/DashboardModal';
import { WorkspaceModal } from './components/modals/WorkspaceModal';
import { UserGroupModal } from './components/modals/UserGroupModal';
import { UserModal, UserSaveResult } from './components/modals/UserModal';
import { DepartmentModal } from './components/modals/DepartmentModal';
import { PowerBiGuideModal } from './components/modals/PowerBiGuideModal';
import { SupabaseConfigModal } from './components/modals/SupabaseConfigModal';
import { FirstLoginPasswordModal } from './components/modals/FirstLoginPasswordModal';
import { CheckCircle2, AlertTriangle, Info, X } from 'lucide-react';
import { motion } from 'motion/react';
import {
  hasAnyAdminPermission,
  isUserAdmin,
  isGroupAdmin,
  getUserGroupForUser,
  canUserModifyTargetUser,
  getUserAllowedWorkspaces,
  isDashboardInWorkspace,
} from './utils/permissions';
import {
  cleanSensitiveStorage,
  sanitizeUser,
  sanitizeUsers,
  sanitizeLicencas,
} from './utils/security';

const CURRENT_USER_STORAGE_KEY = 'mf_hub_current_user_v2';
const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutos de inatividade para logout automático

export default function App() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const currentUserRef = useRef<User | null>(currentUser);
  useEffect(() => {
    currentUserRef.current = currentUser;
  }, [currentUser]);

  const [userGroups, setUserGroups] = useState<UserGroup[]>([]);
  const [departments, setDepartments] = useState<Department[]>([]);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [dashboards, setDashboards] = useState<Dashboard[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [licencas, setLicencas] = useState<PowerBiLicenca[]>([]);
  const [activeLicencaId, setActiveLicencaId] = useState<string | undefined>(undefined);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [supabaseConfig, setSupabaseConfig] = useState<SupabaseConfig>(supabaseService.getConfig());
  const [powerBiAccount, setPowerBiAccount] = useState<PowerBiAccountConfig>({
    email: '',
    password: '',
    accountName: 'Conta Power BI Pro',
    authType: 'direct_credentials',
    autoLoginEnabled: true,
  });

  // Active View & Selection State
  const [selectedDashboard, setSelectedDashboard] = useState<Dashboard | null>(null);

  // Modals state
  const [dashboardModalOpen, setDashboardModalOpen] = useState(false);
  const [editingDashboard, setEditingDashboard] = useState<Dashboard | null>(null);

  const [workspaceModalOpen, setWorkspaceModalOpen] = useState(false);
  const [editingWorkspace, setEditingWorkspace] = useState<Workspace | null>(null);

  const [userGroupModalOpen, setUserGroupModalOpen] = useState(false);
  const [editingUserGroup, setEditingUserGroup] = useState<UserGroup | null>(null);

  const [departmentModalOpen, setDepartmentModalOpen] = useState(false);
  const [editingDepartment, setEditingDepartment] = useState<Department | null>(null);

  const [userModalOpen, setUserModalOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);

  const [guideModalOpen, setGuideModalOpen] = useState(false);
  const [supabaseModalOpen, setSupabaseModalOpen] = useState(false);

  const [loadingSession, setLoadingSession] = useState(true);

  // Global Toast Alert
  const [toast, setToast] = useState<{
    type: 'success' | 'error' | 'info';
    title: string;
    message: string;
  } | null>(null);

  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => {
        setToast(null);
      }, 6000);
      return () => clearTimeout(timer);
    }
  }, [toast]);

  // Load initial data
  const loadData = useCallback(async () => {
    try {
      // Sync branding from Supabase Storage 'Logos' bucket
      brandingService.syncFromSupabase().catch(() => {});

      const [groups, depts, w, lics] = await Promise.all([
        supabaseService.getUserGroups(),
        supabaseService.getDepartments(),
        supabaseService.getWorkspaces(),
        supabaseService.getLicencas(),
      ]);

      const [u, logs, pbiAcc] = await Promise.all([
        supabaseService.getUsers(groups),
        supabaseService.getAuditLogs(),
        supabaseService.getPowerBiAccount(),
      ]);

      // Load dashboards with workspaces & licenses context for pipe string and license name resolution
      const d = await supabaseService.getDashboards(w, lics);

      setUserGroups(groups);
      setDepartments(depts);
      setWorkspaces(w);
      setDashboards(d);
      setUsers(sanitizeUsers(u));
      setAuditLogs(logs);
      setLicencas(lics);

      // Re-sync active currentUser with freshly loaded users and groups and enforce status checks
      setCurrentUser((prev) => {
        if (!prev) return prev;
        const matched = u.find(
          (item) =>
            item.id === prev.id ||
            (item.email && item.email.toLowerCase() === prev.email?.toLowerCase()) ||
            (item.usEmail && item.usEmail.toLowerCase() === prev.email?.toLowerCase()) ||
            (item.name && prev.name && item.name.toLowerCase().trim() === prev.name.toLowerCase().trim())
        );
        let userToSet = matched || prev;

        // Resolve user's actual group from database groups
        const userGroup = getUserGroupForUser(userToSet, groups);
        if (userGroup) {
          userToSet = {
            ...userToSet,
            userGroupId: userGroup.id,
            userGroupName: userGroup.name,
            role: userGroup.role || (isGroupAdmin(userGroup) ? 'admin' : 'user'),
          };
          if (isGroupAdmin(userGroup)) {
            userToSet.allowedWorkspaceIds = w.map((ws) => ws.id);
          }
        } else if (isUserAdmin(userToSet, groups)) {
          const adminGroup = groups.find((g) => isGroupAdmin(g)) || groups[0];
          userToSet = {
            ...userToSet,
            role: 'admin',
            userGroupId: adminGroup?.id || 'grp-admin',
            userGroupName: adminGroup?.name || 'Administrador Master',
            allowedWorkspaceIds: w.map((ws) => ws.id),
          };
        }

        // Check if user status or user profile (group) is inactive
        const groupCheck = supabaseService.checkUserGroupAccess(userToSet, groups);
        if (groupCheck.isBlocked) {
          localStorage.removeItem(CURRENT_USER_STORAGE_KEY);
          setToast({
            type: 'error',
            title: 'Perfil Bloqueado',
            message:
              groupCheck.error ||
              'Seu perfil de acesso está inativo no sistema. Entre em contato com o administrador.',
          });
          return null;
        }

        const sanitized = sanitizeUser(userToSet) as User;
        localStorage.setItem(CURRENT_USER_STORAGE_KEY, JSON.stringify(sanitized));
        return sanitized;
      });
      const isAdminUser = isUserAdmin(currentUserRef.current, groups);
      if (lics && lics.length > 0) {
        const first = lics[0];
        setPowerBiAccount({
          email: first.lcEmail,
          password: isAdminUser ? first.lcSenha : '',
          accountName: first.lcNomeIndent,
          authType: 'direct_credentials',
          autoLoginEnabled: true,
        });
      } else if (pbiAcc) {
        setPowerBiAccount(isAdminUser ? pbiAcc : { ...pbiAcc, password: '' });
      }
    } catch (e) {
      console.error('Error loading data', e);
    }
  }, []);

  useEffect(() => {
    // Purge legacy plain-text passwords and sanitize sensitive keys on app boot
    cleanSensitiveStorage();
    loadData();

    // Check existing Supabase session or localStorage session
    async function checkAuth() {
      try {
        const { session, userProfile } = await supabaseService.getAuthSession();
        if (session && userProfile) {
          const sanitizedProfile = sanitizeUser(userProfile) as User;
          setCurrentUser(sanitizedProfile);
          localStorage.setItem(CURRENT_USER_STORAGE_KEY, JSON.stringify(sanitizedProfile));
        } else {
          const savedUser = localStorage.getItem(CURRENT_USER_STORAGE_KEY);
          if (savedUser) {
            try {
              const parsed: User = JSON.parse(savedUser);
              if (parsed.usStatusConta === 'Ativo' && !parsed.usPrimeiroAcesso) {
                parsed.mustChangePassword = false;
              }
              const sanitizedParsed = sanitizeUser(parsed) as User;
              setCurrentUser(sanitizedParsed);
              localStorage.setItem(CURRENT_USER_STORAGE_KEY, JSON.stringify(sanitizedParsed));
            } catch {}
          }
        }
      } catch (err) {
        console.warn('Auth check error', err);
      } finally {
        setLoadingSession(false);
      }
    }

    checkAuth();

    // Listen to Supabase Auth state changes
    const { data: authListener } = supabaseService.onAuthStateChange(async (event, session) => {
      if (event === 'SIGNED_IN' && session?.user) {
        const profile = await supabaseService.syncUserProfileAfterAuth(session.user);
        if (profile) {
          const sanitizedProfile = sanitizeUser(profile) as User;
          setCurrentUser(sanitizedProfile);
          localStorage.setItem(CURRENT_USER_STORAGE_KEY, JSON.stringify(sanitizedProfile));
        }
      } else if (event === 'SIGNED_OUT') {
        setCurrentUser(null);
        localStorage.removeItem(CURRENT_USER_STORAGE_KEY);
      }
    });

    return () => {
      authListener?.subscription?.unsubscribe();
    };
  }, [loadData]);

  // Auth handler (Login) - Validação Estrita de Senha (Tb_Usuario.Us_Senha)
  const handleLogin = async (
    usernameInput: string,
    passwordInput?: string
  ): Promise<{ success: boolean; error?: string; user?: User } | boolean> => {
    const cleanUser = (usernameInput || '').trim();
    const cleanPass = (passwordInput || '').trim();

    if (!cleanUser) {
      return { success: false, error: 'Por favor, informe seu e-mail corporativo ou usuário.' };
    }

    if (!cleanPass) {
      return { success: false, error: 'Por favor, informe sua senha.' };
    }

    const authResult = await supabaseService.authenticateUser(cleanUser, cleanPass, userGroups);

    if (!authResult.success || !authResult.user) {
      return {
        success: false,
        error: authResult.error || 'Credenciais inválidas. Verifique seu e-mail e senha.',
      };
    }

    const authenticatedUser = authResult.user;
    const updatedUser: User = {
      ...authenticatedUser,
      lastLogin: new Date().toISOString(),
    };

    return { success: true, user: updatedUser };
  };

  const handleLoginSuccess = (updatedUser: User) => {
    setCurrentUser(updatedUser);
    localStorage.setItem(CURRENT_USER_STORAGE_KEY, JSON.stringify(updatedUser));

    // Update in in-memory users list
    setUsers((prevUsers) =>
      prevUsers.some((u) => u.id === updatedUser.id)
        ? prevUsers.map((u) => (u.id === updatedUser.id ? updatedUser : u))
        : [...prevUsers, updatedUser]
    );

    supabaseService.addAuditLog({
      userId: updatedUser.id,
      userName: updatedUser.name,
      action: 'LOGIN',
      details: `Acesso efetuado por ${updatedUser.name} (${updatedUser.email}).`,
    });
  };

  // Handler for First Access Password Change
  const handleFirstPasswordChange = async (newPassword: string) => {
    if (!currentUser) {
      return { success: false, error: 'Sessão inválida ou expirada.' };
    }

    const res = await supabaseService.updateUserPassword(currentUser, newPassword);
    if (res.success && res.updatedUser) {
      const sanitizedUser: User = {
        ...res.updatedUser,
        mustChangePassword: false,
        usPrimeiroAcesso: false,
        usStatusConta: 'Ativo',
      };
      setCurrentUser(sanitizedUser);
      localStorage.setItem(CURRENT_USER_STORAGE_KEY, JSON.stringify(sanitizedUser));

      // Atualiza também na lista local de usuários em memória
      setUsers((prev) =>
        prev.map((u) => (u.id === sanitizedUser.id ? { ...u, ...sanitizedUser } : u))
      );

      setToast({
        title: 'Senha Definida com Sucesso!',
        message: 'Sua senha pessoal foi cadastrada com sucesso. Bem-vindo(a) ao M&F Hub!',
        type: 'success',
      });

      return { success: true };
    }

    return {
      success: false,
      error: res.error || 'Não foi possível cadastrar a nova senha.',
    };
  };

  // Auth handler (Sign Up / Cadastro)
  const handleSignUp = async (
    email: string,
    password: string,
    metadata: { name: string; department?: string }
  ): Promise<{ success: boolean; needsEmailConfirmation?: boolean; error?: string }> => {
    const result = await supabaseService.signUpWithEmail(email, password, {
      name: metadata.name,
      department: metadata.department,
      role: email.toLowerCase().includes('admin') ? 'admin' : 'user',
    });

    if (result.user && result.session) {
      setCurrentUser(result.user);
      localStorage.setItem(CURRENT_USER_STORAGE_KEY, JSON.stringify(result.user));
      // Refresh users list
      const allUsers = await supabaseService.getUsers();
      setUsers(allUsers);
    }

    return {
      success: !result.error && (!!result.user || !!result.session),
      needsEmailConfirmation: result.needsEmailConfirmation,
      error: result.error,
    };
  };

  // Auth handler (Reset Password)
  const handleResetPassword = async (email: string): Promise<{ success: boolean; message: string }> => {
    return supabaseService.resetPasswordForEmail(email);
  };

  const lastActivityRef = useRef<number>(Date.now());

  // Logout handler
  const handleLogout = useCallback(async (reason?: 'inactivity' | 'manual') => {
    if (currentUser) {
      const isAuto = reason === 'inactivity';
      supabaseService.addAuditLog({
        userId: currentUser.id,
        userName: currentUser.name,
        action: 'LOGOUT',
        details: isAuto
          ? `Sessão encerrada automaticamente por inatividade de 5 minutos (${currentUser.name}).`
          : `Sessão encerrada por ${currentUser.name}.`,
      });
    }
    await supabaseService.signOutAuth();
    setCurrentUser(null);
    setSelectedDashboard(null);
    localStorage.removeItem(CURRENT_USER_STORAGE_KEY);

    if (reason === 'inactivity') {
      setToast({
        type: 'info',
        title: 'Sessão Encerrada por Inatividade',
        message: 'Você ficou mais de 5 minutos sem interagir no sistema. Por segurança, sua sessão foi finalizada e você foi redirecionado para a tela de login.',
      });
    }
  }, [currentUser]);

  // Monitoramento de Inatividade do Usuário (Logout Automático após 5 minutos sem interação)
  useEffect(() => {
    if (!currentUser) return;

    // Reset timestamp on user login/mount
    lastActivityRef.current = Date.now();
    let throttleTimeout: any = null;

    const resetActivityTimer = () => {
      if (throttleTimeout) return;
      throttleTimeout = setTimeout(() => {
        lastActivityRef.current = Date.now();
        throttleTimeout = null;
      }, 1000);
    };

    const activityEvents = [
      'mousemove',
      'mousedown',
      'keydown',
      'touchstart',
      'scroll',
      'wheel',
      'pointerdown',
    ];

    activityEvents.forEach((evt) => {
      window.addEventListener(evt, resetActivityTimer, { passive: true });
    });

    // Check inactivity every 4 seconds
    const inactivityInterval = setInterval(() => {
      const now = Date.now();
      const elapsed = now - lastActivityRef.current;

      if (elapsed >= INACTIVITY_TIMEOUT_MS) {
        handleLogout('inactivity');
      }
    }, 4000);

    return () => {
      activityEvents.forEach((evt) => {
        window.removeEventListener(evt, resetActivityTimer);
      });
      clearInterval(inactivityInterval);
      if (throttleTimeout) clearTimeout(throttleTimeout);
    };
  }, [currentUser, handleLogout]);

  // Dashboard CRUD (Tb_Relatorios)
  const handleSaveDashboard = async (
    data: Omit<Dashboard, 'id' | 'createdAt' | 'viewsCount'> & { id?: string }
  ): Promise<{ success: boolean; error?: string }> => {
    const isEdit = !!data.id;
    let targetDash: Dashboard;

    if (data.id) {
      const existing = dashboards.find((d) => d.id === data.id);
      targetDash = {
        ...existing,
        ...data,
        id: data.id,
        viewsCount: existing?.viewsCount || 0,
        createdAt: existing?.createdAt || new Date().toISOString(),
      } as Dashboard;
    } else {
      targetDash = {
        ...data,
        id: 'dash-' + Date.now(),
        viewsCount: 0,
        createdAt: new Date().toISOString(),
      };
    }

    // Update state and local storage immediately for fast UI feedback
    const updatedList = isEdit
      ? dashboards.map((d) => (d.id === targetDash.id ? targetDash : d))
      : [targetDash, ...dashboards];

    setDashboards(updatedList);
    localStorage.setItem('mf_hub_dashboards_v2', JSON.stringify(updatedList));

    // Synchronize workspaces with this dashboard's workspace assignment
    const targetDashTitle = (targetDash.title || targetDash.rlNomeRelatorio || '').trim();
    const selectedWsIds = targetDash.workspaceIds || [];
    const selectedWsNames = (targetDash.rlWorkspaces || '')
      .split('|')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);

    const updatedWorkspaces = workspaces.map((ws) => {
      const wsNameLower = (ws.name || ws.wsNome || '').trim().toLowerCase();
      const wsIdLower = String(ws.id || '').trim().toLowerCase();
      const wsNumId = ws.wsId !== undefined && ws.wsId !== null ? String(ws.wsId).trim().toLowerCase() : '';

      const isSelected =
        selectedWsIds.some((id) => {
          const idClean = String(id).trim().toLowerCase();
          return (
            idClean === wsIdLower ||
            (wsNumId && idClean === wsNumId) ||
            (wsNumId && idClean === `ws-${wsNumId}`) ||
            idClean === wsNameLower
          );
        }) || (wsNameLower && selectedWsNames.includes(wsNameLower));

      let reportTitles = (ws.wsRelatorios || '')
        .split('|')
        .map((t) => t.trim())
        .filter(Boolean);

      const hasReport = reportTitles.some(
        (t) => t.toLowerCase() === targetDashTitle.toLowerCase()
      );

      if (isSelected && !hasReport && targetDashTitle) {
        reportTitles.push(targetDashTitle);
      } else if (!isSelected && hasReport && targetDashTitle) {
        reportTitles = reportTitles.filter(
          (t) => t.toLowerCase() !== targetDashTitle.toLowerCase()
        );
      }

      const newWsRelatorios = reportTitles.join('|');
      if (newWsRelatorios !== (ws.wsRelatorios || '')) {
        return {
          ...ws,
          wsRelatorios: newWsRelatorios,
        };
      }
      return ws;
    });

    setWorkspaces(updatedWorkspaces);
    localStorage.setItem('mf_hub_workspaces_v2', JSON.stringify(updatedWorkspaces));

    // Save to Supabase Tb_Relatorios table
    const result = await supabaseService.saveDashboardToDatabase(
      targetDash,
      currentUser?.name || 'ADM',
      updatedWorkspaces,
      licencas
    );

    // Save modified workspaces to Supabase Tb_Workspaces in background
    for (const ws of updatedWorkspaces) {
      const oldWs = workspaces.find((w) => w.id === ws.id);
      if (oldWs && oldWs.wsRelatorios !== ws.wsRelatorios) {
        supabaseService.saveWorkspaceToDatabase(
          ws,
          undefined,
          currentUser?.name || 'ADM',
          updatedList
        ).catch(() => {});
      }
    }

    if (result.success) {
      setToast({
        type: 'success',
        title: isEdit ? 'Relatório Atualizado' : 'Relatório Criado com Sucesso',
        message: `O relatório "${targetDash.title}" foi salvo e sincronizado com os workspaces selecionados.`,
      });
      // Refresh to ensure IDs and associations are 100% in sync
      loadData();
      return { success: true };
    } else {
      setToast({
        type: 'error',
        title: 'Aviso ao Salvar Relatório',
        message: result.error || 'O relatório foi salvo localmente, mas houve uma falha ao sincronizar.',
      });
      return {
        success: false,
        error: result.error || 'Não foi possível concluir o salvamento do relatório.',
      };
    }

    supabaseService.addAuditLog({
      userId: currentUser?.id || 'admin',
      userName: currentUser?.name || 'Admin',
      action: isEdit ? 'UPDATE_DASHBOARD' : 'CREATE_DASHBOARD',
      details: `Relatório "${data.title}" ${isEdit ? 'atualizado' : 'publicado'}.`,
    });
  };

  const handleDeleteDashboard = async (id: string) => {
    const dash = dashboards.find((d) => d.id === id);
    const dashTitle = (dash?.title || dash?.rlNomeRelatorio || '').trim().toLowerCase();
    const updated = dashboards.filter((d) => d.id !== id);
    setDashboards(updated);

    // Also remove report title from all workspaces
    if (dashTitle) {
      const updatedWorkspaces = workspaces.map((ws) => {
        if (!ws.wsRelatorios) return ws;
        const remaining = ws.wsRelatorios
          .split('|')
          .map((t) => t.trim())
          .filter((t) => t.toLowerCase() !== dashTitle)
          .join('|');
        if (remaining !== ws.wsRelatorios) {
          const newWs = { ...ws, wsRelatorios: remaining };
          supabaseService.saveWorkspaceToDatabase(newWs, undefined, currentUser?.name || 'ADM', updated).catch(() => {});
          return newWs;
        }
        return ws;
      });
      setWorkspaces(updatedWorkspaces);
      localStorage.setItem('mf_hub_workspaces_v2', JSON.stringify(updatedWorkspaces));
    }

    await supabaseService.deleteDashboard(id, dash?.rlId);

    setToast({
      type: 'info',
      title: 'Relatório Removido',
      message: `O relatório "${dash?.title || id}" foi removido com sucesso.`,
    });

    supabaseService.addAuditLog({
      userId: currentUser?.id || 'admin',
      userName: currentUser?.name || 'Admin',
      action: 'DELETE_DASHBOARD',
      details: `Relatório "${dash?.title || id}" removido.`,
    });
  };

  // Apply workspace user access permissions and sync with state, storage and Supabase
  const applyWorkspaceUserAccess = async (targetWs: Workspace, authorizedUserIds: string[]) => {
    const wsId = targetWs.id;
    const wsName = (targetWs.name || targetWs.wsNome || '').trim();
    const wsNumId = targetWs.wsId !== undefined && targetWs.wsId !== null ? String(targetWs.wsId) : '';

    const updatedUsers = users.map((u) => {
      // If user is admin, they always have access anyway
      if (isUserAdmin(u, userGroups)) {
        return u;
      }

      const shouldHaveAccess = authorizedUserIds.includes(u.id);

      let allowedWs = Array.isArray(u.allowedWorkspaceIds) ? [...u.allowedWorkspaceIds] : [];
      let pipeWs = typeof u.usWorkspaces === 'string'
        ? u.usWorkspaces.split('|').map((s) => s.trim()).filter(Boolean)
        : [];

      const hasAccess =
        allowedWs.includes(wsId) ||
        (wsNumId && allowedWs.includes(wsNumId)) ||
        (wsNumId && allowedWs.includes(`ws-${wsNumId}`)) ||
        allowedWs.some((a) => a.toLowerCase() === wsName.toLowerCase()) ||
        pipeWs.some((p) => p.toLowerCase() === wsName.toLowerCase() || (wsNumId && p === wsNumId));

      if (shouldHaveAccess && !hasAccess) {
        allowedWs.push(wsId);
        if (wsName && !pipeWs.some((p) => p.toLowerCase() === wsName.toLowerCase())) {
          pipeWs.push(wsName);
        }
      } else if (!shouldHaveAccess && hasAccess) {
        allowedWs = allowedWs.filter(
          (a) =>
            a !== wsId &&
            a !== wsNumId &&
            a !== `ws-${wsNumId}` &&
            a.toLowerCase() !== wsName.toLowerCase()
        );
        pipeWs = pipeWs.filter(
          (p) =>
            p !== wsId &&
            p !== wsNumId &&
            p !== `ws-${wsNumId}` &&
            p.toLowerCase() !== wsName.toLowerCase()
        );
      } else {
        return u;
      }

      const newUsWorkspaces = pipeWs.join('|');
      return {
        ...u,
        allowedWorkspaceIds: allowedWs,
        usWorkspaces: newUsWorkspaces,
      };
    });

    setUsers(updatedUsers);
    localStorage.setItem('mf_hub_users_v2', JSON.stringify(updatedUsers));

    // Persist changed users to Supabase in background
    for (const u of updatedUsers) {
      const oldU = users.find((ou) => ou.id === u.id);
      if (
        oldU &&
        (JSON.stringify(u.allowedWorkspaceIds) !== JSON.stringify(oldU.allowedWorkspaceIds) ||
          u.usWorkspaces !== oldU.usWorkspaces)
      ) {
        supabaseService.saveUserToDatabase(u, currentUser?.name || 'ADM').catch((err) => {
          console.warn('Sync user workspace access warning:', err);
        });
      }
    }
  };

  const handleSaveWorkspaceUsersAccess = async (workspaceId: string, authorizedUserIds: string[]) => {
    const ws = workspaces.find((w) => w.id === workspaceId);
    if (!ws) return;
    await applyWorkspaceUserAccess(ws, authorizedUserIds);
    setToast({
      type: 'success',
      title: 'Permissões Atualizadas',
      message: `Os acessos dos usuários ao workspace "${ws.name}" foram atualizados com sucesso.`,
    });
  };

  // Workspace CRUD & Tb_Workspaces integration
  const handleSaveWorkspace = async (
    data: Omit<Workspace, 'id' | 'createdAt'> & { id?: string },
    selectedDashboardIds?: string[],
    selectedUserIds?: string[]
  ) => {
    let targetWs: Workspace;
    const existing = data.id ? workspaces.find((w) => w.id === data.id) : null;
    const isEdit = !!data.id;

    // Compute pipe-separated report names/titles if selectedDashboardIds was provided
    let computedWsRelatorios = data.wsRelatorios || existing?.wsRelatorios || '';
    if (selectedDashboardIds !== undefined) {
      const selectedTitles = dashboards
        .filter(
          (d) =>
            selectedDashboardIds.includes(d.id) ||
            (d.rlId !== undefined && d.rlId !== null && selectedDashboardIds.includes(String(d.rlId)))
        )
        .map((d) => (d.title || d.rlNomeRelatorio || '').trim())
        .filter(Boolean);
      computedWsRelatorios = selectedTitles.join('|');
    }

    if (isEdit && data.id) {
      targetWs = {
        ...data,
        id: data.id,
        wsId: existing?.wsId,
        wsRelatorios: computedWsRelatorios,
        wsDataCriacao: existing?.wsDataCriacao || existing?.createdAt || new Date().toISOString(),
        wsUsuarioCriacao: existing?.wsUsuarioCriacao || currentUser?.name || 'ADM',
        createdAt: existing?.createdAt || new Date().toISOString(),
      } as Workspace;
    } else {
      const newWsId = 'ws-' + Date.now();
      targetWs = {
        ...data,
        id: newWsId,
        wsRelatorios: computedWsRelatorios,
        wsDataCriacao: new Date().toISOString(),
        wsUsuarioCriacao: currentUser?.name || 'ADM',
        createdAt: new Date().toISOString(),
      };
    }

    const updatedList = isEdit
      ? workspaces.map((w) => (w.id === targetWs.id ? targetWs : w))
      : [...workspaces, targetWs];

    setWorkspaces(updatedList);
    localStorage.setItem('mf_hub_workspaces_v2', JSON.stringify(updatedList));

    // Save to Supabase Tb_Workspaces table
    const result = await supabaseService.saveWorkspaceToDatabase(
      targetWs,
      selectedDashboardIds,
      currentUser?.name || 'ADM',
      dashboards
    );

    // If selectedDashboardIds was passed, sync the workspaceIds and rlWorkspaces in the dashboards list
    if (selectedDashboardIds !== undefined && targetWs.id) {
      const targetWsId = targetWs.id;
      const targetWsName = (targetWs.name || targetWs.wsNome || '').trim();
      const targetWsNumId = targetWs.wsId !== undefined && targetWs.wsId !== null ? String(targetWs.wsId) : '';

      const updatedDashboards = dashboards.map((d) => {
        const isCurrentlyInWs =
          (d.workspaceIds || []).includes(targetWsId) ||
          (targetWsNumId && (d.workspaceIds || []).includes(targetWsNumId)) ||
          (targetWsNumId && (d.workspaceIds || []).includes(`ws-${targetWsNumId}`));

        const shouldBeInWs =
          selectedDashboardIds.includes(d.id) ||
          (d.rlId !== undefined && d.rlId !== null && selectedDashboardIds.includes(String(d.rlId)));

        let newWsIds = [...(d.workspaceIds || [])];
        let rlWsList = (d.rlWorkspaces || '')
          .split('|')
          .map((s) => s.trim())
          .filter(Boolean);

        if (shouldBeInWs) {
          if (!newWsIds.includes(targetWsId)) {
            newWsIds.push(targetWsId);
          }
          if (targetWsName && !rlWsList.some((n) => n.toLowerCase() === targetWsName.toLowerCase())) {
            rlWsList.push(targetWsName);
          }
        } else {
          newWsIds = newWsIds.filter(
            (id) => id !== targetWsId && id !== targetWsNumId && id !== `ws-${targetWsNumId}` && id.toLowerCase() !== targetWsName.toLowerCase()
          );
          if (targetWsName) {
            rlWsList = rlWsList.filter((n) => n.toLowerCase() !== targetWsName.toLowerCase());
          }
        }

        const newRlWorkspaces = rlWsList.join('|');

        if (
          JSON.stringify(newWsIds) !== JSON.stringify(d.workspaceIds || []) ||
          newRlWorkspaces !== (d.rlWorkspaces || '')
        ) {
          return {
            ...d,
            workspaceIds: newWsIds,
            rlWorkspaces: newRlWorkspaces,
          };
        }
        return d;
      });

      setDashboards(updatedDashboards);
      localStorage.setItem('mf_hub_dashboards_v2', JSON.stringify(updatedDashboards));

      // Synchronize modified dashboards in background to Supabase
      for (const dash of updatedDashboards) {
        const oldDash = dashboards.find((od) => od.id === dash.id);
        const wasChanged =
          JSON.stringify(dash.workspaceIds) !== JSON.stringify(oldDash?.workspaceIds) ||
          dash.rlWorkspaces !== oldDash?.rlWorkspaces;

        if (wasChanged) {
          supabaseService.saveDashboardToDatabase(
            dash,
            currentUser?.name || 'ADM',
            updatedList,
            licencas
          ).catch(() => {});
        }
      }
    }

    // If selectedUserIds was passed, sync the user access permissions for this workspace
    if (selectedUserIds !== undefined && targetWs.id) {
      await applyWorkspaceUserAccess(targetWs, selectedUserIds);
    }

    if (result.success) {
      setToast({
        type: 'success',
        title: isEdit ? 'Workspace Atualizado' : 'Workspace Criado com Sucesso',
        message: `O workspace "${targetWs.name}" foi salvo com sucesso.`,
      });
      // Refresh data to keep all IDs and relationships in sync
      loadData();
    } else {
      setToast({
        type: 'error',
        title: 'Aviso ao Salvar Workspace',
        message: result.error || 'O workspace foi salvo localmente, mas houve uma falha ao sincronizar.',
      });
    }

    supabaseService.addAuditLog({
      userId: currentUser?.id || 'admin',
      userName: currentUser?.name || 'Admin',
      action: isEdit ? 'UPDATE_WORKSPACE' : 'CREATE_WORKSPACE',
      details: `Workspace "${data.name}" ${isEdit ? 'atualizado' : 'criado'}.`,
    });
  };

  const handleDeleteWorkspace = async (id: string) => {
    const ws = workspaces.find((w) => w.id === id);
    const wsName = (ws?.name || ws?.wsNome || '').trim().toLowerCase();
    const wsNumId = ws?.wsId !== undefined && ws?.wsId !== null ? String(ws.wsId) : '';
    const updated = workspaces.filter((w) => w.id !== id);
    setWorkspaces(updated);
    
    // Also remove workspace from dashboards
    const updatedDashboards = dashboards.map((d) => {
      const newWsIds = (d.workspaceIds || []).filter(
        (wsId) => wsId !== id && wsId !== wsNumId && wsId !== `ws-${wsNumId}` && wsId.toLowerCase() !== wsName
      );
      let newRlWs = (d.rlWorkspaces || '')
        .split('|')
        .map((s) => s.trim())
        .filter((s) => s.toLowerCase() !== wsName)
        .join('|');

      const changed =
        newWsIds.length !== (d.workspaceIds || []).length ||
        newRlWs !== (d.rlWorkspaces || '');

      if (changed) {
        const updatedDash = { ...d, workspaceIds: newWsIds, rlWorkspaces: newRlWs };
        supabaseService.saveDashboardToDatabase(updatedDash, currentUser?.name || 'ADM', updated, licencas).catch(() => {});
        return updatedDash;
      }
      return d;
    });

    setDashboards(updatedDashboards);
    localStorage.setItem('mf_hub_dashboards_v2', JSON.stringify(updatedDashboards));

    await supabaseService.deleteWorkspace(id, ws?.wsId);

    setToast({
      type: 'info',
      title: 'Workspace Removido',
      message: `O workspace "${ws?.name || id}" foi removido com sucesso.`,
    });

    supabaseService.addAuditLog({
      userId: currentUser?.id || 'admin',
      userName: currentUser?.name || 'Admin',
      action: 'DELETE_WORKSPACE',
      details: `Workspace "${ws?.name || id}" removido.`,
    });
  };

  // User Group CRUD & Tb_GrupoUsuario integration
  const handleSaveUserGroup = async (
    data: Omit<UserGroup, 'id' | 'createdAt'> & { id?: string }
  ) => {
    let targetGroup: UserGroup;
    const existing = data.id ? userGroups.find((g) => g.id === data.id) : null;
    const isEdit = !!data.id;

    const defaultPerms =
      data.role === 'admin'
        ? [
            'view_home',
            'view_reports',
            'view_workspaces',
            'view_users',
            'view_groups',
            'view_departments',
            'view_licenses',
            'view_branding',
            'view_audit',
            'view_database',
          ]
        : ['view_home', 'view_reports', 'view_workspaces'];

    const permissions =
      data.permissions && data.permissions.length > 0
        ? data.permissions
        : existing?.permissions && existing.permissions.length > 0
        ? existing.permissions
        : defaultPerms;

    const guDfAcessos = permissions.join('|');
    const guStatus = data.status === 'inactive' ? 'Inativo' : 'Ativo';
    const isProfileAdmin =
      data.name.toLowerCase().includes('admin') ||
      data.name.toLowerCase().includes('administrador') ||
      data.role === 'admin';
    const computedRole: UserRole = isProfileAdmin ? 'admin' : 'user';
    const guPrivilegio = isProfileAdmin ? 'Administrador' : 'Membro';

    if (isEdit && data.id) {
      targetGroup = {
        ...data,
        role: computedRole,
        id: data.id,
        guId: existing?.guId,
        guNomePerfil: data.name,
        guStatus,
        guPrivilegio,
        guDfAcessos,
        guDataCriacao: existing?.guDataCriacao || existing?.createdAt || new Date().toISOString(),
        guUsuarioCriacao: existing?.guUsuarioCriacao || currentUser?.name || 'ADM',
        permissions,
        createdAt: existing?.createdAt || new Date().toISOString(),
      } as UserGroup;
    } else {
      const newGrpId = 'grp-' + Date.now();
      targetGroup = {
        ...data,
        id: newGrpId,
        guNomePerfil: data.name,
        guStatus,
        guPrivilegio,
        guDfAcessos,
        guDataCriacao: new Date().toISOString(),
        guUsuarioCriacao: currentUser?.name || 'ADM',
        permissions,
        createdAt: new Date().toISOString(),
      };
    }

    const updatedList = isEdit
      ? userGroups.map((g) => (g.id === targetGroup.id ? targetGroup : g))
      : [...userGroups, targetGroup];

    setUserGroups(updatedList);
    localStorage.setItem('mf_hub_user_groups_v2', JSON.stringify(updatedList));

    // Save to Supabase Tb_GrupoUsuario table
    const result = await supabaseService.saveUserGroupToDatabase(
      targetGroup,
      currentUser?.name || 'ADM'
    );

    if (result.success) {
      if (result.data && result.data[0]?.Gu_Id) {
        const insertedId = result.data[0].Gu_Id;
        targetGroup.guId = insertedId;
        targetGroup.id = `grp-${insertedId}`;
        const finalUpdatedList = isEdit
          ? userGroups.map((g) => (g.id === (data.id || targetGroup.id) ? targetGroup : g))
          : [...userGroups.filter((g) => g.id !== targetGroup.id), targetGroup];
        setUserGroups(finalUpdatedList);
        localStorage.setItem('mf_hub_user_groups_v2', JSON.stringify(finalUpdatedList));
      }

      setToast({
        type: 'success',
        title: isEdit ? 'Perfil Atualizado' : 'Perfil Criado com Sucesso',
        message: `O perfil "${targetGroup.name}" foi salvo com sucesso.`,
      });
      // Refresh to keep IDs and state in sync
      await loadData();
    } else {
      setToast({
        type: 'error',
        title: 'Aviso ao Salvar Perfil',
        message:
          result.error ||
          'O perfil foi salvo localmente, mas houve uma falha ao sincronizar.',
      });
    }

    supabaseService.addAuditLog({
      userId: currentUser?.id || 'admin',
      userName: currentUser?.name || 'Admin',
      action: isEdit ? 'UPDATE_USER_GROUP' : 'CREATE_USER_GROUP',
      details: `Perfil de Usuários "${targetGroup.name}" salvo (${guDfAcessos}).`,
    });
  };

  const handleDeleteUserGroup = async (id: string) => {
    const grp = userGroups.find((g) => g.id === id);
    const updated = userGroups.filter((g) => g.id !== id);
    setUserGroups(updated);
    localStorage.setItem('mf_hub_user_groups_v2', JSON.stringify(updated));

    const res = await supabaseService.deleteUserGroupFromDatabase(id);
    if (res.success) {
      setToast({
        type: 'info',
        title: 'Perfil Excluído',
        message: `O perfil "${grp?.name || id}" foi removido com sucesso.`,
      });
    }

    supabaseService.addAuditLog({
      userId: currentUser?.id || 'admin',
      userName: currentUser?.name || 'Admin',
      action: 'DELETE_USER_GROUP',
      details: `Grupo de Usuários "${grp?.name || id}" excluído.`,
    });
  };

  // Department CRUD & Tb_Departamentos integration
  const handleSaveDepartment = async (data: Omit<Department, 'id' | 'createdAt'> & { id?: string }) => {
    let targetDept: Department;
    const existing = data.id ? departments.find((d) => d.id === data.id) : null;
    const isEdit = !!data.id;

    if (isEdit && data.id) {
      targetDept = {
        ...data,
        id: data.id,
        dsId: existing?.dsId,
        dsNomeDepartamento: data.name,
        dsSigla: data.code,
        dsCor: data.color || '#033838',
        dsDataCriacao: existing?.dsDataCriacao || existing?.createdAt || new Date().toISOString(),
        dsUsuarioCriacao: existing?.dsUsuarioCriacao || currentUser?.name || 'ADM',
        createdAt: existing?.createdAt || new Date().toISOString(),
      } as Department;
    } else {
      const newDeptId = 'dept-' + Date.now();
      targetDept = {
        ...data,
        id: newDeptId,
        dsNomeDepartamento: data.name,
        dsSigla: data.code,
        dsCor: data.color || '#033838',
        dsDataCriacao: new Date().toISOString(),
        dsUsuarioCriacao: currentUser?.name || 'ADM',
        createdAt: new Date().toISOString(),
      };
    }

    const updatedList = isEdit
      ? departments.map((d) => (d.id === targetDept.id ? targetDept : d))
      : [...departments, targetDept];

    setDepartments(updatedList);
    localStorage.setItem('mf_hub_departments_v2', JSON.stringify(updatedList));

    // Save to Supabase Tb_Departamentos table
    const result = await supabaseService.saveDepartmentToDatabase(
      targetDept,
      currentUser?.name || 'ADM'
    );

    if (result.success) {
      setToast({
        type: 'success',
        title: isEdit ? 'Departamento Atualizado' : 'Departamento Criado com Sucesso',
        message: `O setor/departamento "${targetDept.name}" foi salvo com sucesso.`,
      });
      // Refresh to keep IDs and state in sync
      loadData();
    } else {
      setToast({
        type: 'error',
        title: 'Aviso ao Salvar Departamento',
        message: result.error || 'O departamento foi salvo localmente, mas houve uma falha ao sincronizar.',
      });
    }

    supabaseService.addAuditLog({
      userId: currentUser?.id || 'admin',
      userName: currentUser?.name || 'Admin',
      action: isEdit ? 'UPDATE_DEPARTMENT' : 'CREATE_DEPARTMENT',
      details: `Departamento "${data.name}" ${isEdit ? 'atualizado' : 'criado'}.`,
    });
  };

  const handleDeleteDepartment = async (id: string) => {
    const d = departments.find((item) => item.id === id);
    const updated = departments.filter((item) => item.id !== id);
    setDepartments(updated);
    localStorage.setItem('mf_hub_departments_v2', JSON.stringify(updated));

    await supabaseService.deleteDepartment(id, d?.dsId);

    setToast({
      type: 'info',
      title: 'Departamento Removido',
      message: `O departamento "${d?.name || id}" foi removido com sucesso.`,
    });

    supabaseService.addAuditLog({
      userId: currentUser?.id || 'admin',
      userName: currentUser?.name || 'Admin',
      action: 'DELETE_DEPARTMENT',
      details: `Departamento "${d?.name || id}" excluído.`,
    });
  };

  // User CRUD (Tb_Usuario)
  const handleSaveUser = async (
    data: Omit<User, 'id' | 'createdAt'> & { id?: string },
    forceLocal?: boolean
  ): Promise<UserSaveResult> => {
    const creator = currentUser?.email || currentUser?.name || 'Administrador';
    const isCurrentAdmin = isUserAdmin(currentUser, userGroups);

    // Hierarchy check: Users can only edit users at lower levels or themselves
    if (data.id) {
      const existing = users.find((u) => u.id === data.id);
      if (existing && !canUserModifyTargetUser(currentUser, existing, userGroups)) {
        setToast({
          type: 'error',
          title: 'Ação Não Permitida',
          message: 'Você não possui permissão para editar este usuário de acordo com as regras hierárquicas.',
        });
        return { success: false, error: 'Permissão negada para editar usuário.' };
      }
    }

    // Non-admins cannot grant admin role
    if (!isCurrentAdmin && data.role === 'admin') {
      data.role = 'user';
    }

    const cleanEmail = (data.email || '').trim().toLowerCase();

    // Verificação de duplicidade de usuário (por e-mail)
    const duplicate = users.find(
      (u) =>
        (u.email?.trim().toLowerCase() === cleanEmail || u.usEmail?.trim().toLowerCase() === cleanEmail) &&
        (!data.id || (u.id !== data.id && String(u.usId || '') !== String(data.usId || '')))
    );

    if (duplicate && !data.id) {
      const errorMsg = `Não é possível cadastrar: o e-mail "${data.email}" já está em uso por "${duplicate.name || duplicate.usNomeCompleto || duplicate.email}".`;
      setToast({
        type: 'error',
        title: 'Usuário Já Cadastrado',
        message: errorMsg,
      });
      return {
        success: false,
        error: errorMsg,
      };
    }

    if (duplicate && data.id) {
      const errorMsg = `Não é possível alterar para este e-mail: "${data.email}" já pertence a outro usuário ("${duplicate.name || duplicate.usNomeCompleto || duplicate.email}").`;
      setToast({
        type: 'error',
        title: 'E-mail Já em Uso',
        message: errorMsg,
      });
      return {
        success: false,
        error: errorMsg,
      };
    }

    let userToSave: User;
    if (data.id) {
      const existing = users.find((u) => u.id === data.id);
      userToSave = {
        ...(existing || {}),
        ...data,
        id: data.id,
        createdAt: existing?.createdAt || new Date().toISOString(),
      };
    } else {
      userToSave = {
        ...data,
        id: 'user-' + Date.now(),
        createdAt: new Date().toISOString(),
      };
    }

    if (!forceLocal) {
      // Save directly to Supabase with full diagnostics
      const result = await supabaseService.saveUserToDatabase(userToSave, creator);

      if (!result.success) {
        setToast({
          type: 'error',
          title: 'Erro ao Salvar Usuário',
          message: result.error || 'Não foi possível salvar o usuário.',
        });
        return result;
      }
    }

    // Update local state upon database confirmation or local bypass
    let updatedList: User[];
    if (data.id) {
      updatedList = users.map((u) => (u.id === data.id ? userToSave : u));
    } else {
      updatedList = [...users, userToSave];
    }
    setUsers(updatedList);
    localStorage.setItem('mf_hub_users_v2', JSON.stringify(updatedList));

    // Update currentUser if the user being edited is the currently active logged-in user
    if (
      currentUser &&
      (currentUser.id === userToSave.id ||
        currentUser.email.toLowerCase() === userToSave.email.toLowerCase())
    ) {
      const updatedCurrent: User = {
        ...currentUser,
        ...userToSave,
      };
      setCurrentUser(updatedCurrent);
      localStorage.setItem(CURRENT_USER_STORAGE_KEY, JSON.stringify(updatedCurrent));
    }

    setToast({
      type: 'success',
      title: data.id ? 'Usuário Atualizado' : 'Usuário Salvo com Sucesso',
      message: `O usuário "${userToSave.name}" foi salvo com o perfil "${userToSave.userGroupName || 'Membro'}".`,
    });

    supabaseService.addAuditLog({
      userId: currentUser?.id || 'admin',
      userName: currentUser?.name || 'Admin',
      action: data.id ? 'UPDATE_USER' : 'CREATE_USER',
      details: `Usuário "${data.name} (${data.email})" ${data.id ? 'atualizado' : 'criado'} com perfil ${userToSave.userGroupName || userToSave.userGroupId}.`,
    });

    return { success: true };
  };

  const handleDeleteUser = (id: string) => {
    const u = users.find((item) => item.id === id);
    if (!u) return;

    // Hierarchy check: Users can only delete users below them or themselves
    if (!canUserModifyTargetUser(currentUser, u, userGroups)) {
      setToast({
        type: 'error',
        title: 'Ação Não Permitida',
        message: 'Você não possui permissão para excluir este usuário de acordo com as regras hierárquicas.',
      });
      return;
    }

    const updated = users.filter((item) => item.id !== id);
    setUsers(updated);
    supabaseService.deleteUser(id, u?.usId);

    supabaseService.addAuditLog({
      userId: currentUser?.id || 'admin',
      userName: currentUser?.name || 'Admin',
      action: 'DELETE_USER',
      details: `Usuário "${u?.name || id}" excluído com sucesso.`,
    });
  };

  // Save / Delete Licença Power BI (Tb_Licencas)
  const handleSaveLicenca = async (lic: PowerBiLicenca): Promise<{ success: boolean; error?: string }> => {
    const isExisting = licencas.some((l) => l.id === lic.id || (lic.lcId && l.lcId === lic.lcId));
    const res = await supabaseService.saveLicencaToDatabase(
      lic,
      currentUser?.name || currentUser?.email || 'ADM'
    );

    let updatedList: PowerBiLicenca[];
    if (isExisting) {
      updatedList = licencas.map((l) =>
        l.id === lic.id || (lic.lcId && l.lcId === lic.lcId) ? lic : l
      );
    } else {
      updatedList = [...licencas, lic];
    }

    setLicencas(updatedList);
    localStorage.setItem('mf_hub_licencas_v2', JSON.stringify(updatedList));

    // Update active powerBiAccount
    setPowerBiAccount({
      email: lic.lcEmail,
      password: lic.lcSenha,
      accountName: lic.lcNomeIndent,
      authType: 'direct_credentials',
      autoLoginEnabled: true,
    });

    if (res.success) {
      setToast({
        type: 'success',
        title: isExisting ? 'Conta Atualizada' : 'Conta Salva com Sucesso',
        message: `Conta "${lic.lcNomeIndent}" salva com sucesso.`,
      });

      supabaseService.addAuditLog({
        userId: currentUser?.id || 'admin',
        userName: currentUser?.name || 'Admin',
        action: isExisting ? 'UPDATE_LICENCA' : 'CREATE_LICENCA',
        details: `Conta Power BI "${lic.lcNomeIndent}" salva com sucesso.`,
      });
      return { success: true };
    } else {
      return {
        success: true,
        error: `Salvo localmente (Aviso: ${res.error || 'sem conexão'}).`,
      };
    }
  };

  const handleDeleteLicenca = async (id: string, lcId?: number | string) => {
    const target = licencas.find((l) => l.id === id || (lcId && l.lcId === lcId));
    const updated = licencas.filter((l) => l.id !== id && (!lcId || l.lcId !== lcId));
    setLicencas(updated);
    await supabaseService.deleteLicenca(id, lcId);

    setToast({
      type: 'info',
      title: 'Conta Removida',
      message: `Conta "${target?.lcNomeIndent || id}" removida com sucesso.`,
    });

    supabaseService.addAuditLog({
      userId: currentUser?.id || 'admin',
      userName: currentUser?.name || 'Admin',
      action: 'DELETE_LICENCA',
      details: `Conta "${target?.lcNomeIndent || id}" excluída de Tb_Licencas.`,
    });
  };

  // Track dashboard view
  const handleTrackView = useCallback((dashId: string) => {
    setDashboards((prevDashboards) => {
      const targetDash = prevDashboards.find((d) => d.id === dashId);
      if (targetDash && currentUser) {
        supabaseService.addAuditLog({
          userId: currentUser.id,
          userName: currentUser.name,
          action: 'VIEW_DASHBOARD',
          details: `Visualizou o relatório "${targetDash.title}".`,
          dashboardId: targetDash.id,
          dashboardTitle: targetDash.title,
        });
      }
      const updated = prevDashboards.map((d) =>
        d.id === dashId ? { ...d, viewsCount: (d.viewsCount || 0) + 1 } : d
      );
      supabaseService.saveDashboards(updated);
      return updated;
    });
  }, [currentUser]);

  // Reset demo data
  const handleResetData = () => {
    supabaseService.resetToDefaults();
    loadData();
    setSupabaseModalOpen(false);
  };

  // Loading session initial check
  if (loadingSession) {
    return (
      <div className="min-h-screen bg-[#f8fafc] flex flex-col items-center justify-center">
        <div className="w-10 h-10 border-3 border-[#033838] border-t-transparent rounded-full animate-spin mb-4" />
        <p className="text-xs font-bold text-slate-600 uppercase tracking-wider">Verificando sessão segura M&amp;F Hub...</p>
      </div>
    );
  }

  // Render Login Screen if not authenticated (Protected Access)
  if (!currentUser) {
    return (
      <>
        <LoginScreen
          onLogin={handleLogin}
          onLoginSuccess={handleLoginSuccess}
          onSignUp={handleSignUp}
          onResetPassword={handleResetPassword}
          departments={departments}
        />
        <SupabaseConfigModal
          isOpen={supabaseModalOpen}
          onClose={() => setSupabaseModalOpen(false)}
          config={supabaseConfig}
          onConfigUpdated={(cfg) => setSupabaseConfig(cfg)}
          onResetData={handleResetData}
        />
        {/* Global Toast Alert on Login */}
        {toast && (
          <div className="fixed bottom-6 right-6 z-50 max-w-md animate-in slide-in-from-bottom-5 fade-in">
            <div
              className={`p-4 rounded-2xl shadow-xl border flex items-start gap-3 ${
                toast.type === 'error'
                  ? 'bg-rose-50 border-rose-300 text-rose-900'
                  : toast.type === 'success'
                  ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
                  : 'bg-slate-900 border-slate-700 text-white'
              }`}
            >
              {toast.type === 'error' ? (
                <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
              ) : toast.type === 'success' ? (
                <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
              ) : (
                <Info className="w-5 h-5 text-teal-400 shrink-0 mt-0.5" />
              )}
              <div className="flex-1 text-xs">
                <h5 className="font-extrabold">{toast.title}</h5>
                <p className="mt-0.5 opacity-90 leading-relaxed">{toast.message}</p>
              </div>
              <button
                onClick={() => setToast(null)}
                className="p-1 rounded-lg hover:bg-black/5 text-slate-400 hover:text-white transition cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
      className="min-h-screen bg-[#f8fafc] text-slate-900 flex flex-col font-sans selection:bg-[#033838]/15 selection:text-[#033838]"
    >
      {/* Global Header */}
      <Header
        currentUser={currentUser}
        userGroups={userGroups}
        supabaseConfig={supabaseConfig}
        onOpenSupabaseModal={() => setSupabaseModalOpen(true)}
        onOpenGuideModal={() => setGuideModalOpen(true)}
        onLogout={handleLogout}
      />

      {/* Main App Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 flex flex-col">
        {selectedDashboard ? (
          /* Interactive Power BI Report Viewer */
          <div className="flex-1 flex flex-col min-h-[700px]">
            <PowerBiViewer
              dashboard={selectedDashboard}
              workspaces={workspaces}
              currentUser={currentUser}
              onBack={() => setSelectedDashboard(null)}
              onTrackView={handleTrackView}
              onUpdateDashboard={handleSaveDashboard}
            />
          </div>
        ) : (
          /* Painel de Gestão Unificado (com Visualizar Hub integrado) */
          <AdminPanel
            workspaces={workspaces}
            dashboards={dashboards}
            users={users}
            userGroups={userGroups}
            departments={departments}
            auditLogs={auditLogs}
            supabaseConfig={supabaseConfig}
            currentUser={currentUser}
            onOpenDashboardModal={(d) => {
              setEditingDashboard(d || null);
              setDashboardModalOpen(true);
            }}
            onSaveDashboard={handleSaveDashboard}
            onRefreshData={loadData}
            onDeleteDashboard={handleDeleteDashboard}
            onOpenWorkspaceModal={(w) => {
              setEditingWorkspace(w || null);
              setWorkspaceModalOpen(true);
            }}
            onDeleteWorkspace={handleDeleteWorkspace}
            onOpenUserGroupModal={(g) => {
              setEditingUserGroup(g || null);
              setUserGroupModalOpen(true);
            }}
            onDeleteUserGroup={handleDeleteUserGroup}
            onOpenDepartmentModal={(dept) => {
              setEditingDepartment(dept || null);
              setDepartmentModalOpen(true);
            }}
            onDeleteDepartment={handleDeleteDepartment}
            onOpenUserModal={(u) => {
              setEditingUser(u || null);
              setUserModalOpen(true);
            }}
            onDeleteUser={handleDeleteUser}
            onOpenSupabaseModal={() => setSupabaseModalOpen(true)}
            onSelectDashboardPreview={(d) => setSelectedDashboard(d)}
            onOpenGuideModal={() => setGuideModalOpen(true)}
            onSaveWorkspaceUsers={handleSaveWorkspaceUsersAccess}
          />
        )}
      </main>

      {/* Global Modals */}
      <DashboardModal
        isOpen={dashboardModalOpen}
        onClose={() => {
          setDashboardModalOpen(false);
          setEditingDashboard(null);
        }}
        onSave={handleSaveDashboard}
        editingDashboard={editingDashboard}
        workspaces={workspaces}
        licencas={licencas}
      />

      <WorkspaceModal
        isOpen={workspaceModalOpen}
        onClose={() => {
          setWorkspaceModalOpen(false);
          setEditingWorkspace(null);
        }}
        onSave={handleSaveWorkspace}
        editingWorkspace={editingWorkspace}
        dashboards={dashboards}
        users={users}
        userGroups={userGroups}
        departments={departments}
        currentUser={currentUser}
      />

      <UserGroupModal
        isOpen={userGroupModalOpen}
        onClose={() => {
          setUserGroupModalOpen(false);
          setEditingUserGroup(null);
        }}
        onSave={handleSaveUserGroup}
        editingGroup={editingUserGroup}
      />

      <UserModal
        isOpen={userModalOpen}
        onClose={() => {
          setUserModalOpen(false);
          setEditingUser(null);
        }}
        onSave={handleSaveUser}
        editingUser={editingUser}
        existingUsers={users}
        userGroups={userGroups}
        departments={departments}
        currentUser={currentUser}
        onOpenDepartmentModal={() => {
          setEditingDepartment(null);
          setDepartmentModalOpen(true);
        }}
        onOpenSupabaseConfig={() => {
          setSupabaseModalOpen(true);
        }}
        workspaces={workspaces}
      />

      <DepartmentModal
        isOpen={departmentModalOpen}
        onClose={() => {
          setDepartmentModalOpen(false);
          setEditingDepartment(null);
        }}
        onSave={handleSaveDepartment}
        editingDepartment={editingDepartment}
      />

      <PowerBiGuideModal
        isOpen={guideModalOpen}
        onClose={() => setGuideModalOpen(false)}
      />

      <SupabaseConfigModal
        isOpen={supabaseModalOpen}
        onClose={() => setSupabaseModalOpen(false)}
        config={supabaseConfig}
        onConfigUpdated={(cfg) => setSupabaseConfig(cfg)}
        onResetData={handleResetData}
      />

      {/* Modal de Primeiro Acesso - Cadastro Obrigatório de Senha */}
      {currentUser && currentUser.mustChangePassword && (
        <FirstLoginPasswordModal
          user={currentUser}
          onPasswordChanged={handleFirstPasswordChange}
          onCancelLogout={() => handleLogout('manual')}
        />
      )}

      {/* Global Toast Alert */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 max-w-md animate-in slide-in-from-bottom-5 fade-in">
          <div
            className={`p-4 rounded-2xl shadow-xl border flex items-start gap-3 ${
              toast.type === 'error'
                ? 'bg-rose-50 border-rose-300 text-rose-900'
                : toast.type === 'success'
                ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
                : 'bg-slate-900 border-slate-700 text-white'
            }`}
          >
            {toast.type === 'error' ? (
              <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
            ) : toast.type === 'success' ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
            ) : (
              <Info className="w-5 h-5 text-teal-400 shrink-0 mt-0.5" />
            )}
            <div className="flex-1 text-xs">
              <h5 className="font-extrabold">{toast.title}</h5>
              <p className="mt-0.5 opacity-90 leading-relaxed">{toast.message}</p>
            </div>
            <button
              onClick={() => setToast(null)}
              className="p-1 rounded-lg hover:bg-black/5 text-slate-500 transition cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </motion.div>
  );
}
