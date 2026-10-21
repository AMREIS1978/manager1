<?php
declare(strict_types=1);

function out(array $data,int $status=200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data,JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function fail(string $message,int $status=400): never { out(['error'=>$message],$status); }
function users_file(): string { return __DIR__.'/users.json'; }
function load_users(): array {
    $file=users_file();
    if(!is_file($file)) return [];
    $fp=fopen($file,'rb'); if(!$fp) return [];
    flock($fp,LOCK_SH); $raw=stream_get_contents($fp) ?: '[]'; flock($fp,LOCK_UN); fclose($fp);
    $data=json_decode($raw,true); return is_array($data)?$data:[];
}
function save_users(array $users): void {
    $file=users_file(); $tmp=$file.'.'.bin2hex(random_bytes(4)).'.tmp';
    $fp=fopen($tmp,'wb'); if(!$fp) throw new RuntimeException('Não foi possível guardar as contas.');
    flock($fp,LOCK_EX); fwrite($fp,json_encode(array_values($users),JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT)); fflush($fp); flock($fp,LOCK_UN); fclose($fp);
    if(!rename($tmp,$file)) throw new RuntimeException('Não foi possível concluir a gravação das contas.'); @chmod($file,0600);
}
function start_app_session(): void {
    if(session_status()===PHP_SESSION_ACTIVE) return;
    ini_set('session.use_strict_mode','1'); ini_set('session.use_only_cookies','1'); session_name('manager1_session');
    $secure=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off');
    session_set_cookie_params(['lifetime'=>2592000,'path'=>'/','secure'=>$secure,'httponly'=>true,'samesite'=>'Lax']); session_start();
    if(empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(32));
}
function csrf_check(): void { if(!hash_equals($_SESSION['csrf']??'',$_SERVER['HTTP_X_CSRF_TOKEN']??'')) fail('Sessão expirada. Atualiza a página.',403); }
function body(): array {
    $raw=file_get_contents('php://input',false,null,0,20001) ?: ''; if(strlen($raw)>20000) fail('Pedido demasiado grande.',413);
    $d=json_decode($raw,true); if(!is_array($d)) fail('Pedido inválido.'); return $d;
}
function normalize_login(string $value): string { $value=trim($value); if($value===''||strlen($value)>120) throw new RuntimeException('Utilizador ou email inválido.'); return strtolower($value); }
function validate_password(string $password): void { if(strlen($password)<6||strlen($password)>128) throw new RuntimeException('A palavra-passe deve ter 6 a 128 caracteres.'); }
function validate_handle(string $handle): string { $handle=trim($handle); if(!preg_match('/^[\p{L}\p{N}_-]{3,24}$/u',$handle)) throw new RuntimeException('O nome de jogador deve ter 3 a 24 letras/números, sem espaços.'); return $handle; }
function validate_club(string $club): string { $club=trim($club); if(strlen($club)<3||strlen($club)>72||preg_match('/[<>\x00-\x1f]/u',$club)) throw new RuntimeException('Nome de clube inválido.'); return $club; }
function public_profile(array $u): array { return ['id'=>$u['id'],'handle'=>$u['handle'],'club'=>$u['club'],'formation'=>$u['formation']??'433','ready'=>count($u['squad']??[])===11,'created'=>$u['created']??null,'email'=>$u['email']??null]; }
function current_user(array $users): ?array { $uid=$_SESSION['uid']??null; if(!$uid)return null; foreach($users as $u)if(($u['id']??'')===$uid)return $u; return null; }
function find_user_index(array $users,string $login): int {
    $login=normalize_login($login); foreach($users as $i=>$u){
        if(strtolower((string)($u['login']??''))===$login) return $i;
        if(!empty($u['email'])&&strtolower((string)$u['email'])===$login) return $i;
        if(!empty($u['handle'])&&strtolower((string)$u['handle'])===$login) return $i;
    } return -1;
}
function new_user(array &$users,string $login,string $club,string $password,string $role='player',?string $handle=null): array {
    $login=normalize_login($login); validate_password($password); $club=validate_club($club);
    if($handle===null){ $base=filter_var($login,FILTER_VALIDATE_EMAIL)?(strstr($login,'@',true)?:'jogador'):$login; $base=preg_replace('/[^A-Za-z0-9_]/','_',$base); $handle=validate_handle(substr($base,0,24)); }
    else $handle=validate_handle($handle);
    if(find_user_index($users,$login)>=0) throw new RuntimeException('Já existe uma conta com esse utilizador ou email.');
    foreach($users as $u)if(strtolower((string)($u['handle']??''))===strtolower($handle)) throw new RuntimeException('Esse nome de jogador já está ocupado.');
    $u=['id'=>bin2hex(random_bytes(16)),'login'=>$login,'email'=>filter_var($login,FILTER_VALIDATE_EMAIL)?$login:null,'handle'=>$handle,'club'=>$club,'role'=>$role,'password_hash'=>password_hash($password,PASSWORD_DEFAULT),'formation'=>'433','squad'=>[],'created'=>gmdate('c')];
    $users[]=$u; save_users($users); return $u;
}
