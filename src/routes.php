<?php

use Slim\App;
use Slim\Http\Request;
use Slim\Http\Response;

return function (App $app) {
    $container = $app->getContainer();

    $app->get('/', function (Request $request, Response $response, array $args) use ($container) {
        // Log message
        $container->get('logger')->info("Slim-Skeleton '/' route");

        // Render index view
        return $container->get('renderer')->render($response, 'index.phtml', $args);
    });

    $app->any('/api/admin/login', function (Request $request, Response $response, array $args) {
        if ($request->getMethod() == "OPTIONS") {
            return $response
                ->withHeader('Access-Control-Allow-Origin', '*')
                ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization');
        }
        $input = (array)$request->getParsedBody();
        $this->logger->info("Admin login attempt || " . json_encode($input));
        if (isset($input['loginhash'])) {
            $q = $this->db->prepare('SELECT admin_username as username, admin_password as password, display_pic as dp, admin_name as name FROM admins WHERE admin_logintoken=:logintoken');
            $q->execute(array('logintoken' => $input['loginhash']));
            $r = $q->fetch(PDO::FETCH_OBJ);
            $pass = $r->password;
        } else {
            $q = $this->db->prepare('SELECT admin_username as username, admin_password as password, display_pic as dp, admin_name as name FROM admins WHERE admin_username=:username');
            $q->execute(array('username' => $input['username']));
            $r = $q->fetch(PDO::FETCH_OBJ);
            $pass = trim($input['password']);
        }
        if (isset($r->username)) {
            // User found, continue checking
            if ($r->password == $pass) {
                // User found, password matched
                if (isset($input['loginhash'])) {
                    $loginhash = $input['loginhash'];
                } else {
                    $loginhash = hash("sha256", $r->username . $r->password . time());
                    $u = $this->db->prepare('UPDATE admins SET admin_logintoken=:loginhash WHERE admin_username=:username');
                    $u->execute(array('username' => $input['username'], 'loginhash' => $loginhash));
                }
                return $response
                    ->withHeader('Access-Control-Allow-Origin', '*')
                    ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
                    ->withJson(array('success' => 1, 'name' => $r->name, 'dp' => $r->dp, 'token' => $loginhash));
            }
            // User found, password did not match
            return $response
                ->withHeader('Access-Control-Allow-Origin', '*')
                ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
                ->withJson(array('success' => 0, 'reason' => 'Invalid Password'));
        }
        // User not found
        return $response
            ->withHeader('Access-Control-Allow-Origin', '*')
            ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
            ->withJson(array('success' => 0, 'reason' => 'User not found'));
    });
};
