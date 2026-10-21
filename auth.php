<?php
declare(strict_types=1);
require __DIR__.'/private/auth-core.php';
start_app_session();
$route=(string)($_GET['route']??'me');
$method=(string)($_SERVER['REQUEST_METHOD']??'GET');
$users=load_users();
$me=current_user($users);
try {
    if($route==='me'&&$method==='GET') out(['signedIn'=>(bool)$me,'csrf'=>$_SESSION['csrf'],'registration'=>true,'admin'=>(($me['role']??'')==='admin'),'profile'=>$me?array_merge(public_profile($me),['squad'=>$me['squad']??[]]):null]);
    if($route==='auth-status'&&$method==='GET') out(['ok'=>true,'registration'=>true,'minPassword'=>6,'signedIn'=>(bool)$me,'admin'=>(($me['role']??'')==='admin')]);
    if($method!=='GET') csrf_check();

    if($route==='login'&&$method==='POST'){
        $b=body(); $login=(string)($b['username']??$b['email']??''); $password=(string)($b['password']??''); validate_password($password);
        $idx=find_user_index($users,$login); if($idx<0||!password_verify($password,(string)($users[$idx]['password_hash']??''))) fail('Utilizador/email ou palavra-passe incorretos.',401);
        session_regenerate_id(true); $_SESSION['uid']=$users[$idx]['id']; $_SESSION['csrf']=bin2hex(random_bytes(32)); out(['ok'=>true,'csrf'=>$_SESSION['csrf']]);
    }
    if($route==='register'&&$method==='POST'){
        $b=body(); $login=(string)($b['username']??$b['email']??''); $password=(string)($b['password']??''); $club=(string)($b['club']??''); $handle=isset($b['handle'])?(string)$b['handle']:null;
        $u=new_user($users,$login,$club,$password,'player',$handle); session_regenerate_id(true); $_SESSION['uid']=$u['id']; $_SESSION['csrf']=bin2hex(random_bytes(32)); out(['ok'=>true,'csrf'=>$_SESSION['csrf']],201);
    }
    if($route==='logout'&&$method==='POST'){
        $_SESSION=[]; session_regenerate_id(true); $_SESSION['csrf']=bin2hex(random_bytes(32)); out(['ok'=>true,'csrf'=>$_SESSION['csrf']]);
    }
    if(!$me) fail('Entra com a tua conta para jogar online.',401);

    if($route==='profile'&&$method==='POST'){
        $b=body(); $idx=find_user_index($users,(string)$me['login']); if($idx<0) fail('Conta não encontrada.',404);
        $users[$idx]['handle']=validate_handle((string)($b['handle']??$users[$idx]['handle'])); $users[$idx]['club']=validate_club((string)($b['club']??$users[$idx]['club'])); save_users($users); out(['ok'=>true]);
    }
    if($route==='squad'&&$method==='PUT'){
        $b=body(); $ids=$b['ids']??[]; if(!is_array($ids)||count($ids)!==11) fail('Escolhe 11 jogadores.',400);
        $idx=find_user_index($users,(string)$me['login']); $users[$idx]['squad']=array_values($ids); $users[$idx]['formation']=(string)($b['formation']??'433'); save_users($users); out(['ok'=>true]);
    }
    if($route==='players'&&$method==='GET') out(['players'=>array_values(array_map('public_profile',array_filter($users,fn($u)=>($u['id']??'')!==($me['id']??''))))]);
    if($route==='matches'&&$method==='GET') out(['matches'=>[]]);
    if($route==='leaderboard'&&$method==='GET') out(['rows'=>[]]);
    if($route==='challenge'&&$method==='POST') out(['ok'=>true,'id'=>bin2hex(random_bytes(8))],201);
    if($route==='respond'&&$method==='POST') out(['ok'=>true,'result'=>null]);

    if(str_starts_with($route,'admin/')){
        if(($me['role']??'')!=='admin') fail('Acesso reservado ao administrador.',403);
        if($route==='admin/users'&&$method==='GET') out(['users'=>array_map(fn($u)=>array_merge(public_profile($u),['role'=>$u['role']]),$users)]);
        if($route==='admin/create'&&$method==='POST'){
            $b=body(); $login=(string)($b['username']??$b['email']??''); $password=(string)($b['password']??''); $club=(string)($b['club']??''); $handle=isset($b['handle'])?(string)$b['handle']:null;
            $u=new_user($users,$login,$club,$password,'player',$handle); out(['ok'=>true,'profile'=>public_profile($u)],201);
        }
        if($route==='admin/reset'&&$method==='POST'){
            $b=body(); $id=(string)($b['id']??''); $password=(string)($b['password']??''); validate_password($password); $found=false;
            foreach($users as &$u){ if(($u['id']??'')===$id){$u['password_hash']=password_hash($password,PASSWORD_DEFAULT);$found=true;break;} } unset($u);
            if(!$found) fail('Utilizador não encontrado.',404); save_users($users); out(['ok'=>true]);
        }
    }
    fail('Operação não encontrada.',404);
} catch(Throwable $e){ $code=$e->getCode(); if($code<400||$code>599)$code=400; fail($e->getMessage(),$code); }
