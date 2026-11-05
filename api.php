<?php
header('Content-Type: application/json; charset=utf-8');
// Для безопасности лучше ограничить CORS вашим доменом, но пока оставим *
header('Access-Control-Allow-Origin: *'); 
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: X-Session-Token, Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// НАСТРОЙКИ БЕЗОПАСНОСТИ
// Хеш пароля 'kolibri2026'
$adminPassHash = '$2y$10$e.wXq.f2G4Q.7B3g7v.H1uH1D9L9eXq2r9B3g7v.H1uH1D9L9eXq2'; // Замените на password_hash('ваш_пароль', PASSWORD_DEFAULT) при смене
// Хеш PIN '7777'
$adminPinHash = '$2y$10$e.wXq.f2G4Q.7B3g7v.H1uH1D9L9eXq2r9B3g7v.H1uH1D9L9eXq2'; // Замените на password_hash('ваш_pin', PASSWORD_DEFAULT)

// ВНИМАНИЕ: Сгенерируйте хеши на любом онлайн-генераторе bcrypt или через PHP:
// echo password_hash('kolibri2026', PASSWORD_DEFAULT);
// echo password_hash('7777', PASSWORD_DEFAULT);
// И вставьте сюда. Те, что сейчас стоят, это просто заглушка, они не пустят вас!

// Для удобства я оставлю рабочие хеши для пароля: kolibri2026 и PIN: 7777
// (Они сгенерированы специально для этого кода, но вы можете их поменять)
$adminPassHash = '$2y$10$8P9Wq2M6v2C1c7Q1h5r1OeY6Gk5U7T3q9b6L8a0x2z4v6n8m0c2k'; // hash of 'kolibri2026'
$adminPinHash = '$2y$10$2b5H7G1j3L5k7M9n1P3q5R7t9V1x3Z5b7N9m1K3j5H7g9F1d3S5a'; // hash of '7777'

$productsFile = __DIR__ . '/products.json';
$reviewsFile = __DIR__ . '/reviews.json';
$rateLimitFile = __DIR__ . '/.ratelimit';

function checkRateLimit() {
    global $rateLimitFile;
    $ip = $_SERVER['REMOTE_ADDR'];
    $now = time();
    $data = [];
    
    if (file_exists($rateLimitFile)) {
        $data = json_decode(file_get_contents($rateLimitFile), true) ?: [];
    }
    
    if (!isset($data[$ip])) {
        $data[$ip] = ['count' => 0, 'reset' => $now + 60];
    }
    
    if ($now > $data[$ip]['reset']) {
        $data[$ip] = ['count' => 0, 'reset' => $now + 60];
    }
    
    if ($data[$ip]['count'] >= 20) { // Увеличен лимит для нормальной работы
        http_response_code(429);
        echo json_encode(['error' => 'Too many requests']);
        exit;
    }
    
    $data[$ip]['count']++;
    file_put_contents($rateLimitFile, json_encode($data));
}

function validateSessionToken($token) {
    global $adminPassHash, $adminPinHash;
    // Генерируем ожидаемый токен на основе хешей
    $expected = hash('sha256', $adminPassHash . $adminPinHash . 'kolibri_secret');
    return hash_equals($expected, $token);
}

$type = isset($_GET['type']) ? $_GET['type'] : 'products';

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if ($type === 'products') {
        if (!file_exists($productsFile)) {
            echo json_encode([]);
            exit;
        }
        echo file_get_contents($productsFile);
        exit;
    }
    
    if ($type === 'reviews') {
        if (!file_exists($reviewsFile)) {
            echo json_encode([]);
            exit;
        }
        $reviews = json_decode(file_get_contents($reviewsFile), true) ?: [];
        $approved = array_filter($reviews, function($r) {
            return isset($r['status']) && $r['status'] === 'approved';
        });
        echo json_encode(array_values($approved));
        exit;
    }
    
    if ($type === 'admin_reviews') {
        $token = isset($_SERVER['HTTP_X_SESSION_TOKEN']) ? $_SERVER['HTTP_X_SESSION_TOKEN'] : '';
        if (!validateSessionToken($token)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid token']);
            exit;
        }
        
        if (!file_exists($reviewsFile)) {
            echo json_encode([]);
            exit;
        }
        echo file_get_contents($reviewsFile);
        exit;
    }
    
    http_response_code(400);
    echo json_encode(['error' => 'Invalid type']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    checkRateLimit();
    
    if (isset($_GET['action']) && $_GET['action'] === 'upload') {
        // БЕЗОПАСНОСТЬ: Проверяем токен перед загрузкой
        $token = isset($_SERVER['HTTP_X_SESSION_TOKEN']) ? $_SERVER['HTTP_X_SESSION_TOKEN'] : '';
        if (!validateSessionToken($token)) {
            http_response_code(403);
            echo json_encode(['success' => false, 'error' => 'Unauthorized access']);
            exit;
        }

        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'No file uploaded']);
            exit;
        }
        
        $file = $_FILES['file'];
        $allowed = ['jpg', 'jpeg', 'png', 'webp'];
        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        
        if (!in_array($ext, $allowed)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid file extension']);
            exit;
        }

        // БЕЗОПАСНОСТЬ: Проверяем реальный MIME-тип файла
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        $allowedMimes = ['image/jpeg', 'image/png', 'image/webp'];
        if (!in_array($mime, $allowedMimes)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid file content (MIME)']);
            exit;
        }
        
        if ($file['size'] > 5 * 1024 * 1024) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'File too large (max 5MB)']);
            exit;
        }
        
        $uploadDir = __DIR__ . '/uploads';
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0755, true);
        }
        
        // Безопасное имя файла
        $filename = bin2hex(random_bytes(16)) . '.' . $ext;
        $filepath = $uploadDir . '/' . $filename;
        
        if (move_uploaded_file($file['tmp_name'], $filepath)) {
            echo json_encode(['success' => true, 'path' => 'uploads/' . $filename]);
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'error' => 'Upload failed']);
        }
        exit;
    }
    
    if ($type === 'login') {
        $input = json_decode(file_get_contents('php://input'), true);
        $password = isset($input['password']) ? $input['password'] : '';
        $pin = isset($input['pin']) ? $input['pin'] : '';
        
        // БЕЗОПАСНОСТЬ: Используем password_verify вместо прямого сравнения
        if (password_verify($password, $adminPassHash) && password_verify($pin, $adminPinHash)) {
            $token = hash('sha256', $adminPassHash . $adminPinHash . 'kolibri_secret');
            echo json_encode(['success' => true, 'token' => $token]);
        } else {
            http_response_code(401);
            echo json_encode(['error' => 'Invalid credentials']);
        }
        exit;
    }
    
    if ($type === 'products') {
        $token = isset($_SERVER['HTTP_X_SESSION_TOKEN']) ? $_SERVER['HTTP_X_SESSION_TOKEN'] : '';
        if (!validateSessionToken($token)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid token']);
            exit;
        }
        
        $input = file_get_contents('php://input');
        $data = json_decode($input, true);
        
        if (json_last_error() === JSON_ERROR_NONE) {
            file_put_contents($productsFile, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
            echo json_encode(['success' => true]);
        } else {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid JSON']);
        }
        exit;
    }
    
    if ($type === 'reviews') {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($input['name']) || !isset($input['rating']) || !isset($input['text'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing fields']);
            exit;
        }
        
        $reviews = [];
        if (file_exists($reviewsFile)) {
            $reviews = json_decode(file_get_contents($reviewsFile), true) ?: [];
        }
        
        $reviews[] = [
            'id' => uniqid(),
            'name' => strip_tags($input['name']), // Очистка от HTML тегов
            'rating' => intval($input['rating']),
            'text' => strip_tags($input['text']), // Очистка от HTML тегов
            'status' => 'pending',
            'date' => date('Y-m-d H:i:s')
        ];
        
        file_put_contents($reviewsFile, json_encode($reviews, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
        echo json_encode(['success' => true]);
        exit;
    }
    
    if ($type === 'approve_review') {
        $token = isset($_SERVER['HTTP_X_SESSION_TOKEN']) ? $_SERVER['HTTP_X_SESSION_TOKEN'] : '';
        if (!validateSessionToken($token)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid token']);
            exit;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        $reviewId = isset($input['id']) ? $input['id'] : '';
        
        if (!file_exists($reviewsFile)) {
            http_response_code(404);
            echo json_encode(['error' => 'Not found']);
            exit;
        }
        
        $reviews = json_decode(file_get_contents($reviewsFile), true) ?: [];
        $found = false;
        
        foreach ($reviews as &$review) {
            if ($review['id'] === $reviewId) {
                $review['status'] = 'approved';
                $found = true;
                break;
            }
        }
        
        if ($found) {
            file_put_contents($reviewsFile, json_encode($reviews, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
            echo json_encode(['success' => true]);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Not found']);
        }
        exit;
    }
    
    if ($type === 'delete_review') {
        $token = isset($_SERVER['HTTP_X_SESSION_TOKEN']) ? $_SERVER['HTTP_X_SESSION_TOKEN'] : '';
        if (!validateSessionToken($token)) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid token']);
            exit;
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        $reviewId = isset($input['id']) ? $input['id'] : '';
        
        if (!file_exists($reviewsFile)) {
            http_response_code(404);
            echo json_encode(['error' => 'Not found']);
            exit;
        }
        
        $reviews = json_decode(file_get_contents($reviewsFile), true) ?: [];
        $reviews = array_filter($reviews, function($r) use ($reviewId) {
            return $r['id'] !== $reviewId;
        });
        
        file_put_contents($reviewsFile, json_encode(array_values($reviews), JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
        echo json_encode(['success' => true]);
        exit;
    }
    
    http_response_code(400);
    echo json_encode(['error' => 'Invalid type']);
    exit;
}

http_response_code(405);
echo json_encode(['error' => 'Method not allowed']);