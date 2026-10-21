<?php
declare(strict_types=1);
require __DIR__.'/private/auth-core.php';
start_app_session();
$success=false;$error='';
if($_SERVER['REQUEST_METHOD']==='POST'){
    try{
        if(!hash_equals($_SESSION['csrf']??'',(string)($_POST['csrf']??''))) throw new RuntimeException('Sessão expirada. Atualize a página.');
        $users=load_users();
        if(array_filter($users,fn($u)=>($u['role']??'')==='admin')) throw new RuntimeException('A conta de administrador já está criada.');
        $u=new_user($users,(string)($_POST['admin_login']??''),(string)($_POST['admin_club']??'TalentScout'),(string)($_POST['admin_password']??''),'admin',(string)($_POST['admin_handle']??'Administrador'));
        session_regenerate_id(true); $_SESSION['uid']=$u['id']; $_SESSION['csrf']=bin2hex(random_bytes(32)); $success=true;
    }catch(Throwable $e){$error=$e->getMessage();}
}
function h($v){return htmlspecialchars((string)$v,ENT_QUOTES,'UTF-8');}
header('Cache-Control: no-store');
?><!doctype html><html lang="pt-PT"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Configurar Manager1</title><style>body{font:16px system-ui;background:#081522;color:#eef7ff;max-width:680px;margin:40px auto;padding:20px}.box{background:#102638;border:1px solid #31506a;border-radius:14px;padding:22px}input{width:100%;box-sizing:border-box;padding:12px;margin:6px 0 14px;background:#071725;color:white;border:1px solid #426079;border-radius:8px}button,a{display:inline-block;background:#b7ff6a;color:#10220d;border:0;padding:12px 16px;border-radius:8px;font-weight:800;text-decoration:none}.err{background:#4c2730;padding:12px;border-radius:8px}</style><div class="box"><h1>TalentScout Manager1</h1><?php if($success):?><h2>Administrador criado</h2><p>A sessão ficou iniciada.</p><a href="index.html">Abrir aplicação</a><?php else:?><?php if($error):?><div class="err"><?=h($error)?></div><?php endif;?><p>Crie uma única vez a conta de administrador. As credenciais ficam apenas no servidor e nunca aparecem no site.</p><form method="post"><input type="hidden" name="csrf" value="<?=h($_SESSION['csrf'])?>"><label>Utilizador ou email<input name="admin_login" required maxlength="120"></label><label>Nome visível<input name="admin_handle" value="Administrador" required maxlength="24"></label><label>Clube<input name="admin_club" value="TalentScout" required maxlength="36"></label><label>Palavra-passe<input type="password" name="admin_password" minlength="6" maxlength="128" required></label><button type="submit">Criar administrador</button></form><?php endif;?></div></html>
