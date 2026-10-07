import { Board, User } from '../types';

/**
 * Normaliza strings removendo acentos e caracteres especiais para comparação segura
 */
function cleanStr(s?: string): string {
  return (s || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]/g, ' ')
    .trim();
}

/**
 * Filtra a lista de colaboradores para exibir estritamente aqueles pertencentes
 * à mesma Área de Trabalho (Quadro Kanban).
 * 
 * Regras aplicadas:
 * 1. Membros explicitamente vinculados à Área de Trabalho (board.allowedUserIds)
 * 2. Correspondência semântica entre a Área de Trabalho (ex: MIS/BI, Modelagem) e o Setor/Departamento do colaborador
 * 3. Colaboradores de mesmo setor/departamento do criador/quadro
 * 4. Preserva colaboradores já atribuídos na atividade (selectedAssigneeIds) para garantir integridade
 * 5. Garante a presença do usuário atual (currentUser) para permitir auto-atribuição
 */
export function getWorkspaceUsers(
  board: Board | undefined,
  allUsers: User[],
  currentUser?: User,
  selectedAssigneeIds: string[] = []
): User[] {
  if (!allUsers || allUsers.length === 0) return [];
  if (!board) return allUsers;

  // 1. Se a Área de Trabalho possui membros explicitamente definidos em allowedUserIds
  if (board.allowedUserIds && board.allowedUserIds.length > 0) {
    const allowedSet = new Set<string>(board.allowedUserIds);
    if (board.ownerId) allowedSet.add(board.ownerId);
    if (currentUser?.id) allowedSet.add(currentUser.id);
    selectedAssigneeIds.forEach(id => {
      if (id) allowedSet.add(id);
    });

    const matched = allUsers.filter(u => allowedSet.has(u.id));
    if (matched.length > 0) {
      return matched;
    }
  }

  // 2. Correspondência semântica por Área de Trabalho vs Setor/Departamento/Perfil
  const boardTitleClean = cleanStr(board.title);
  const boardDescClean = cleanStr(board.description);
  const boardText = `${boardTitleClean} ${boardDescClean}`;

  const isMisBi = boardText.includes('mis') || boardText.includes('bi');
  const isModelagem = boardText.includes('modelagem');

  // Tokens com ao menos 3 caracteres
  const boardTokens = boardText
    .split(/\s+/)
    .filter(t => t.length >= 3 && !['quadro', 'esteira', 'demandas', 'entregas', 'equipe', 'time'].includes(t));

  const filtered = allUsers.filter(u => {
    // Preserva sempre usuários já atribuídos
    if (selectedAssigneeIds.includes(u.id)) return true;

    // Preserva o usuário atual
    if (currentUser?.id && u.id === currentUser.id) return true;

    const uDeptClean = cleanStr(u.department);
    const uSecClean = cleanStr(u.sector);
    const uNameClean = cleanStr(u.name);
    const userAllText = `${uDeptClean} ${uSecClean} ${uNameClean}`;

    // Usuário com perfil transversal (ex: Gestão Mis/Modelagem)
    if (userAllText.includes('gestao') && (userAllText.includes('mis') || userAllText.includes('modelagem'))) {
      return true;
    }

    // Regras específicas da empresa para Área MIS/BI
    if (isMisBi) {
      if (
        uSecClean.includes('mis') || 
        uSecClean.includes('bi') || 
        uDeptClean.includes('mis') || 
        uDeptClean.includes('bi') ||
        uDeptClean.includes('inteligencia') ||
        uNameClean.includes('mis') ||
        uNameClean.includes('bi')
      ) {
        return true;
      }
    }

    // Regras específicas da empresa para Área Modelagem
    if (isModelagem) {
      if (
        uSecClean.includes('modelagem') || 
        uDeptClean.includes('modelagem') ||
        uNameClean.includes('modelagem')
      ) {
        return true;
      }
    }

    // Casamento genérico por tokens de setor/departamento com título do quadro
    if (boardTokens.length > 0) {
      const match = boardTokens.some(tok => 
        (uSecClean && uSecClean.includes(tok)) || 
        (uDeptClean && uDeptClean.includes(tok))
      );
      if (match) return true;
    }

    // Colaboradores que compartilham o mesmo setor que o usuário logado
    if (currentUser?.sector) {
      const curSecClean = cleanStr(currentUser.sector);
      if (curSecClean && uSecClean && curSecClean === uSecClean) {
        return true;
      }
    }

    return false;
  });

  // Se a filtragem encontrou pessoas da área de trabalho, retorna
  if (filtered.length > 0) {
    return filtered;
  }

  // Fallback seguro: se o usuário atual tiver setor/departamento específico, filtra por ele
  if (currentUser?.department && currentUser.department.toLowerCase() !== 'geral') {
    const sameDept = allUsers.filter(u => 
      u.department?.toLowerCase() === currentUser.department.toLowerCase() ||
      selectedAssigneeIds.includes(u.id) ||
      u.id === currentUser.id
    );
    if (sameDept.length > 0) return sameDept;
  }

  // Se nenhum critério isolou, retorna a lista completa
  return allUsers;
}
