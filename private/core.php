<?php
declare(strict_types=1);

function json_out(array $data,int $status=200): never {
  http_response_code($status);
  header('Content-Type: application/json; charset=utf-8');
  header('Cache-Control: no-store');
  echo json_encode($data,JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE);
  exit;
}
function fail_json(string $message,int $status=400): never { json_out(['error'=>$message],$status); }
function app_config(): array {
  $file=__DIR__.'/config.php';
  if(!is_file($file)) return ['installed'=>false];
  $c=require $file;
  return is_array($c)?$c:['installed'=>false];
}
function users_file(): string { return __DIR__.'/users.json'; }
function load_users(): array {
  $file=users_file();
  if(!is_file($file)) return [];
  $fp=fopen($file,'rb'); if(!$fp) return [];
  flock($fp,LOCK_SH); $raw=stream_get_contents($fp)?:'[]'; flock($fp,LOCK_UN); fclose($fp);
  $data=json_decode($raw,true);
  return is_array($data)?$data:[];
}
function save_users(array $users): void {
  $file=users_file();
  $tmp=$file.'.tmp';
  $fp=fopen($tmp,'wb'); if(!$fp) throw new RuntimeException('Não foi possível gravar utilizadores.');
  flock($fp,LOCK_EX); fwrite($fp,json_encode(array_values($users),JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT)); fflush($fp); flock($fp,LOCK_UN); fclose($fp);
  if(!rename($tmp,$file)) throw new RuntimeException('Não foi possível concluir a gravação.');
  @chmod($file,0600);
}
function public_user(array $u): array {
  return ['id'=>$u['id'],'email'=>$u['email'],'handle'=>$u['handle'],'club'=>$u['club'],'role'=>$u['role'],'created'=>$u['created']];
}
function validate_email(string $email): string {
  $email=strtolower(trim($email));
  if(!filter_var($email,FILTER_VALIDATE_EMAIL)||strlen($email)>120) throw new RuntimeException('Email inválido.');
  return $email;
}
function validate_password(string $password): void {
  if(strlen($password)<6||strlen($password)>128) throw new RuntimeException('A palavra-passe deve ter 6 a 128 caracteres.');
}
function validate_handle(string $handle): string {
  $handle=trim($handle);
  if(!preg_match('/^[\p{L}\p{N}_-]{3,24}$/u',$handle)) throw new RuntimeException('O nome de jogador deve ter 3 a 24 letras/números, sem espaços.');
  return $handle;
}
function validate_club(string $club): string {
  $club=trim($club);
  if(mb_strlen($club)<3||mb_strlen($club)>36||preg_match('/[<>\x00-\x1f]/u',$club)) throw new RuntimeException('O clube deve ter 3 a 36 caracteres.');
  return $club;
}
function start_secure_session(): void {
  if(session_status()===PHP_SESSION_ACTIVE) return;
  ini_set('session.use_strict_mode','1'); ini_set('session.use_only_cookies','1');
  session_name('manager1_session');
  $secure=(!empty($_SERVER['HTTPS'])&&$_SERVER['HTTPS']!=='off');
  session_set_cookie_params(['lifetime'=>2592000,'path'=>'/','secure'=>$secure,'httponly'=>true,'samesite'=>'Lax']);
  session_start();
  if(empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(32));
}
function body_json(): array {
  $raw=file_get_contents('php://input',false,null,0,20001)?:'';
  if(strlen($raw)>20000) throw new RuntimeException('Pedido demasiado grande.');
  $d=json_decode($raw,true); if(!is_array($d)) throw new RuntimeException('Pedido inválido.');
  return $d;
}
function require_csrf(): void {
  $got=$_SERVER['HTTP_X_CSRF_TOKEN']??'';
  if(!hash_equals($_SESSION['csrf']??'',$got)) fail_json('Sessão expirada. Atualize a página.',403);
}
function current_user(array $users): ?array {
  $id=$_SESSION['uid']??null;
  if(!$id) return null;
  foreach($users as $u) if(($u['id']??'')===$id) return $u;
  return null;
}
function new_id(): string { return bin2hex(random_bytes(16)); }
