import { User, PermissionLevel } from '../types';

export const DEFAULT_PERMISSION_LEVELS: PermissionLevel[] = [
  {
    id: 'admin',
    name: 'Administrador',
    code: 'ADMIN',
    description: 'Acesso total irrestrito: configurações, gestão de usuários, criação/edição/exclusão de cartões e quadros.',
    color: '#EF4444',
    canAccessSettings: true,
    canCreateCards: true,
    canEditCards: true,
    canDeleteCards: true,
    canCreateBoards: true,
    canEditBoards: true,
    canDeleteBoards: true,
    canMoveCards: true,
    isSystem: true,
    createdAt: new Date().toISOString()
  }
];

export interface UserEffectivePermissions {
  canAccessSettings: boolean;
  canCreateCards: boolean;
  canEditCards: boolean;
  canDeleteCards: boolean;
  canCreateBoards: boolean;
  canEditBoards: boolean;
  canDeleteBoards: boolean;
  canMoveCards: boolean;
  roleName: string;
  roleColor: string;
  roleCode: string;
}

export function getUserPermissions(
  user: User | null | undefined,
  roles: PermissionLevel[] = []
): UserEffectivePermissions {
  if (!user) {
    return {
      canAccessSettings: false,
      canCreateCards: false,
      canEditCards: false,
      canDeleteCards: false,
      canCreateBoards: false,
      canEditBoards: false,
      canDeleteBoards: false,
      canMoveCards: false,
      roleName: 'Não autenticado',
      roleColor: '#64748B',
      roleCode: 'ANON'
    };
  }

  // Look up by role ID or case-insensitive match
  const matchedRole = roles.find(
    r => r.id === user.role || (r.name || '').toLowerCase() === (user.role || '').toLowerCase()
  );

  if (matchedRole) {
    return {
      canAccessSettings: Boolean(matchedRole.canAccessSettings),
      canCreateCards: Boolean(matchedRole.canCreateCards),
      canEditCards: Boolean(matchedRole.canEditCards),
      canDeleteCards: Boolean(matchedRole.canDeleteCards),
      canCreateBoards: Boolean(matchedRole.canCreateBoards ?? matchedRole.canAccessSettings),
      canEditBoards: Boolean(matchedRole.canEditBoards ?? matchedRole.canAccessSettings),
      canDeleteBoards: Boolean(matchedRole.canDeleteBoards ?? false),
      canMoveCards: Boolean(matchedRole.canMoveCards ?? matchedRole.canEditCards),
      roleName: matchedRole.name,
      roleColor: matchedRole.color || '#3B82F6',
      roleCode: matchedRole.code || matchedRole.name.substring(0, 4).toUpperCase()
    };
  }

  // Fallback defaults for legacy roles
  if (user.role === 'admin') {
    return {
      canAccessSettings: true,
      canCreateCards: true,
      canEditCards: true,
      canDeleteCards: true,
      canCreateBoards: true,
      canEditBoards: true,
      canDeleteBoards: true,
      canMoveCards: true,
      roleName: 'Administrador',
      roleColor: '#EF4444',
      roleCode: 'ADMIN'
    };
  }

  if (user.role === 'manager') {
    return {
      canAccessSettings: true,
      canCreateCards: true,
      canEditCards: true,
      canDeleteCards: true,
      canCreateBoards: true,
      canEditBoards: true,
      canDeleteBoards: false,
      canMoveCards: true,
      roleName: 'Tech Lead / Líder',
      roleColor: '#F59E0B',
      roleCode: 'LEAD'
    };
  }

  if (user.role === 'member') {
    return {
      canAccessSettings: false,
      canCreateCards: true,
      canEditCards: true,
      canDeleteCards: false,
      canCreateBoards: false,
      canEditBoards: false,
      canDeleteBoards: false,
      canMoveCards: true,
      roleName: 'Membro',
      roleColor: '#3B82F6',
      roleCode: 'MEMBER'
    };
  }

  // Default viewer / read-only
  return {
    canAccessSettings: false,
    canCreateCards: false,
    canEditCards: false,
    canDeleteCards: false,
    canCreateBoards: false,
    canEditBoards: false,
    canDeleteBoards: false,
    canMoveCards: false,
    roleName: user.role || 'Visualizador',
    roleColor: '#10B981',
    roleCode: 'VIEWER'
  };
}
