<?php
// FFORUM - A all-in-one PHP file forum system

// --- CONFIGURATION ---
$dbFile = __DIR__ . '/data.db';
session_start();

// --- DATABASE INIT ---
function getPDO() {
    global $dbFile;
    $pdo = new PDO('sqlite:' . $dbFile);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
}

if (!file_exists($dbFile)) {
    $pdo = getPDO();
    $pdo->exec("
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            admin_level INTEGER DEFAULT 0,
            profile_pic TEXT,
            banned INTEGER DEFAULT 0
        );
        CREATE TABLE forums (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            creator_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            image TEXT,
            FOREIGN KEY (creator_id) REFERENCES users(id)
        );
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            forum_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            image TEXT,
            FOREIGN KEY (forum_id) REFERENCES forums(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            admin_level INTEGER DEFAULT 3,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ");

    $founderUser = 'founder';
    $founderPass = bin2hex(random_bytes(30));
    $hash = password_hash($founderPass, PASSWORD_DEFAULT);
    $founderPic = getDefaultProfilePic($founderUser);
    $pdo->prepare("INSERT INTO users (username, password, admin_level, profile_pic) VALUES (?,?,?,?)")
        ->execute([$founderUser, $hash, 2, $founderPic]);
    $founderId = $pdo->lastInsertId();
    $pdo->exec("INSERT INTO admin (user_id, admin_level) VALUES ($founderId, 3)");
    file_put_contents(__DIR__ . '/founder.txt', "Founder username: $founderUser\nFounder password: $founderPass\n");
}

// --- HELPER FUNCTIONS ---
function isLoggedIn() { return isset($_SESSION['user']); }
function getUser() { return $_SESSION['user'] ?? null; }
function getBadge($level) {
    if ($level == 1) return '<span class="badge badge-mod">MOD</span>';
    if ($level == 2) return '<span class="badge badge-admin">ADMIN</span>';
    if ($level == 3) return '<span class="badge badge-founder">FOUNDER</span>';
    return '';
}
function isAdmin() {
    $u = getUser();
    return $u && ($u['admin_level'] >= 2);
}
function isFounder() {
    $u = getUser();
    return $u && ($u['admin_level'] == 3);
}
function isMod() {
    $u = getUser();
    return $u && ($u['admin_level'] == 1);
}
function getUserById($id) {
    $pdo = getPDO();
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id=?");
    $stmt->execute([$id]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}
function renderImage($base64) {
    if (!$base64) return '';
    if (strpos($base64, 'data:image/') === 0) {
        return "<img src='$base64' class='img-preview'>";
    }
    return "<img src='data:image/png;base64,$base64' class='img-preview'>";
}
function handleImageUpload($fileField) {
    if (!isset($_FILES[$fileField]) || $_FILES[$fileField]['error'] !== UPLOAD_ERR_OK) return null;
    $f = $_FILES[$fileField];
    $allowed = ['image/jpeg', 'image/png', 'image/gif'];
    $info = getimagesize($f['tmp_name']);
    if (!$info || !in_array($info['mime'], $allowed)) return null;
    $data = file_get_contents($f['tmp_name']);
    $base64 = 'data:' . $info['mime'] . ';base64,' . base64_encode($data);
    return $base64;
}
function getDefaultProfilePic($username) {
    $letters = strtoupper(substr(preg_replace('/[^a-zA-Z0-9]/', '', $username), 0, 2));
    return "https://ui-avatars.com/api/?name=$letters&background=ececec&color=636e72&rounded=true&size=44";
}
function isValidUsername($username) {
    return preg_match('/^[a-zA-Z0-9_-]{1,32}$/', $username);
}

// --- REGISTER ---
if (isset($_POST['register'])) {
    $username = trim($_POST['username']);
    if (!$username) {
        $error = "Username required.";
    } elseif (!isValidUsername($username)) {
        $error = "Username must be 1-32 characters, only letters, numbers, - and _ allowed.";
    } else {
        $pdo = getPDO();
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username=?");
        $stmt->execute([$username]);
        if ($stmt->fetch()) {
            $error = "Username already exists.";
        } else {
            $password = bin2hex(random_bytes(30));
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $profilePic = handleImageUpload('profile_pic');
            if (!$profilePic) {
                $profilePic = getDefaultProfilePic($username);
            }
            $pdo->prepare("INSERT INTO users (username, password, profile_pic) VALUES (?,?,?)")->execute([$username, $hash, $profilePic]);
            $success = "Account created! Username: <b>$username</b> Password: <b>$password</b> (save it!)";
        }
    }
}

// --- LOGIN ---
if (isset($_POST['login'])) {
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    $pdo = getPDO();
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username=?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($user && $user['banned']) {
        $error = "Your account is banned.";
    } elseif ($user && password_verify($password, $user['password'])) {
        $adminStmt = $pdo->prepare("SELECT * FROM admin WHERE user_id=?");
        $adminStmt->execute([$user['id']]);
        $admin = $adminStmt->fetch(PDO::FETCH_ASSOC);
        if ($admin) $user['admin_level'] = 3;
        $_SESSION['user'] = $user;
        header("Location: index.php");
        exit;
    } else {
        $error = "Invalid login.";
    }
}

// --- LOGOUT ---
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit;
}

// --- EDIT PROFILE ---
if (isLoggedIn() && isset($_POST['edit_profile'])) {
    $pdo = getPDO();
    $u = getUser();
    $profilePic = handleImageUpload('profile_pic');
    if ($profilePic) {
        $pdo->prepare("UPDATE users SET profile_pic=? WHERE id=?")->execute([$profilePic, $u['id']]);
        $_SESSION['user']['profile_pic'] = $profilePic;
    }
    $success = "Profile updated!";
}

// --- CREATE FORUM ---
if (isLoggedIn() && isset($_POST['create_forum'])) {
    $title = trim($_POST['title']);
    $image = handleImageUpload('forum_image');
    if ($title) {
        $pdo = getPDO();
        $pdo->prepare("INSERT INTO forums (title, creator_id, image) VALUES (?,?,?)")->execute([$title, getUser()['id'], $image]);
        header("Location: index.php");
        exit;
    }
}

// --- DELETE FORUM ---
if (isLoggedIn() && isset($_GET['delete_forum'])) {
    $forumId = (int)$_GET['delete_forum'];
    $pdo = getPDO();
    $stmt = $pdo->prepare("SELECT * FROM forums WHERE id=?");
    $stmt->execute([$forumId]);
    $forum = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($forum) {
        $canDelete = false;
        if ($forum['creator_id'] == getUser()['id']) $canDelete = true;
        if (isAdmin() || isFounder()) $canDelete = true;
        if ($canDelete) {
            $pdo->prepare("DELETE FROM comments WHERE forum_id=?")->execute([$forumId]);
            $pdo->prepare("DELETE FROM forums WHERE id=?")->execute([$forumId]);
            header("Location: index.php");
            exit;
        }
    }
}

// --- ADD COMMENT ---
if (isLoggedIn() && isset($_POST['add_comment'])) {
    $forumId = (int)$_POST['forum_id'];
    $content = trim($_POST['content']);
    $image = handleImageUpload('comment_image');
    if ($content) {
        $pdo = getPDO();
        $pdo->prepare("INSERT INTO comments (forum_id, user_id, content, image) VALUES (?,?,?,?)")
            ->execute([$forumId, getUser()['id'], $content, $image]);
        header("Location: index.php?forum=$forumId");
        exit;
    }
}

// --- DELETE COMMENT ---
if (isLoggedIn() && isset($_GET['delete_comment'])) {
    $commentId = (int)$_GET['delete_comment'];
    $pdo = getPDO();
    $stmt = $pdo->prepare("SELECT * FROM comments WHERE id=?");
    $stmt->execute([$commentId]);
    $comment = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($comment) {
        $canDelete = false;
        if ($comment['user_id'] == getUser()['id']) $canDelete = true;
        if (isAdmin() || isFounder() || isMod()) $canDelete = true;
        $forumStmt = $pdo->prepare("SELECT * FROM forums WHERE id=?");
        $forumStmt->execute([$comment['forum_id']]);
        $forum = $forumStmt->fetch(PDO::FETCH_ASSOC);
        if ($forum && $forum['creator_id'] == getUser()['id']) $canDelete = true;
        if ($canDelete) {
            $pdo->prepare("DELETE FROM comments WHERE id=?")->execute([$commentId]);
            header("Location: index.php?forum=" . $comment['forum_id']);
            exit;
        }
    }
}

// --- ADMIN DASHBOARD ---
if (isFounder() && isset($_GET['admin'])) {
    $pdo = getPDO();
    // Promote user
    if (isset($_POST['promote_user'])) {
        $uid = (int)$_POST['user_id'];
        $level = (int)$_POST['level'];
        $pdo->prepare("UPDATE users SET admin_level=? WHERE id=?")->execute([$level, $uid]);
    }
    // Delete user
    if (isset($_POST['delete_user'])) {
        $uid = (int)$_POST['user_id'];
        $pdo->prepare("DELETE FROM users WHERE id=?")->execute([$uid]);
    }
    // Ban user
    if (isset($_POST['ban_user'])) {
        $uid = (int)$_POST['user_id'];
        $pdo->prepare("UPDATE users SET banned=1 WHERE id=?")->execute([$uid]);
    }
    // Unban user
    if (isset($_POST['unban_user'])) {
        $uid = (int)$_POST['user_id'];
        $pdo->prepare("UPDATE users SET banned=0 WHERE id=?")->execute([$uid]);
    }
    // Reset password
    if (isset($_POST['reset_password'])) {
        $uid = (int)$_POST['user_id'];
        $newPass = bin2hex(random_bytes(8));
        $hash = password_hash($newPass, PASSWORD_DEFAULT);
        $pdo->prepare("UPDATE users SET password=? WHERE id=?")->execute([$hash, $uid]);
        $reset_success = "Password for user ID $uid reset to: <b>$newPass</b>";
    }
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>FFORUM - Admin Dashboard</title>
        <style>
            body {
                background: #f5f6fa;
                font-family: 'Segoe UI', Arial, sans-serif;
                margin: 0;
                padding: 0;
            }
            .admin-container {
                max-width: 1100px;
                margin: 40px auto;
                background: #fff;
                border-radius: 16px;
                box-shadow: 0 6px 32px rgba(0,0,0,0.13);
                padding: 36px 44px 44px 44px;
            }
            h2 {
                font-family: 'Montserrat', Arial, sans-serif;
                font-size: 2.2em;
                color: #2d3436;
                text-align: center;
                margin-bottom: 28px;
                letter-spacing: 2px;
            }
            .admin-section {
                margin-bottom: 38px;
            }
            .admin-table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 18px;
                background: #f9fafb;
                border-radius: 8px;
                overflow: hidden;
            }
            .admin-table th, .admin-table td {
                padding: 12px 10px;
                border-bottom: 1px solid #e1e1e1;
                text-align: left;
            }
            .admin-table th {
                background: #f1f2f6;
                color: #636e72;
                font-size: 1.05em;
            }
            .admin-table tr:last-child td {
                border-bottom: none;
            }
            .admin-actions button, .admin-actions select {
                margin-right: 6px;
                padding: 6px 12px;
                border-radius: 5px;
                border: none;
                font-size: 1em;
            }
            .admin-actions button {
                background: #0984e3;
                color: #fff;
                cursor: pointer;
                transition: background 0.2s;
            }
            .admin-actions button:hover {
                background: #74b9ff;
            }
            .admin-actions .delete-btn {
                background: #d63031;
                color: #fff;
            }
            .admin-actions .delete-btn:hover {
                background: #ff7675;
            }
            .admin-actions .ban-btn {
                background: #fdcb6e;
                color: #2d3436;
            }
            .admin-actions .ban-btn:hover {
                background: #ffeaa7;
            }
            .admin-actions .unban-btn {
                background: #00b894;
                color: #fff;
            }
            .admin-actions .unban-btn:hover {
                background: #55efc4;
            }
            .admin-actions .reset-btn {
                background: #636e72;
                color: #fff;
            }
            .admin-actions .reset-btn:hover {
                background: #b2bec3;
            }
            .profile-pic {
                width: 38px;
                height: 38px;
                border-radius: 50%;
                object-fit: cover;
                margin-right: 8px;
                vertical-align: middle;
                border: 2px solid #dfe6e9;
            }
            .img-preview {
                max-width: 80px;
                max-height: 80px;
                border-radius: 8px;
                margin: 2px 0 2px 6px;
                vertical-align: middle;
                box-shadow: 0 1px 6px rgba(0,0,0,0.07);
            }
            .badge {
                font-weight: bold;
                padding: 2px 8px;
                border-radius: 6px;
                font-size: 0.9em;
                margin-left: 6px;
            }
            .badge-mod { background: #d6eaff; color: #0984e3; }
            .badge-admin { background: #ffe6e6; color: #d63031; }
            .badge-founder { background: #f3e6ff; color: #6c3483; }
            .banned-label {
                color: #d63031;
                font-weight: bold;
                margin-left: 8px;
            }
            .back-link {
                display: inline-block;
                margin-top: 18px;
                color: #636e72;
                text-decoration: none;
                font-size: 1.1em;
            }
            .back-link:hover { color: #0984e3; }
            .alert-success {
                background: #eafaf1;
                color: #27ae60;
                padding: 10px 18px;
                border-radius: 8px;
                margin-bottom: 18px;
                font-size: 1.1em;
            }
        </style>
    </head>
    <body>
    <div class="admin-container">
        <h2><span style="color: blue;">FF</span><span style="color: white;">OR</span><span style="color: red;">UM</span> - Admin Dashboard</h2>
        <a href="index.php" class="back-link">&larr; Back to forum</a>
        <?php if (!empty($reset_success)) echo "<div class='alert-success'>$reset_success</div>"; ?>
        <div class="admin-section">
            <h3>Users</h3>
            <table class="admin-table">
                <tr>
                    <th>ID</th>
                    <th>Profile</th>
                    <th>Username</th>
                    <th>Level</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
                <?php
                $users = $pdo->query("SELECT * FROM users")->fetchAll(PDO::FETCH_ASSOC);
                foreach ($users as $u) {
                    echo "<tr>";
                    echo "<td>{$u['id']}</td>";
                    echo "<td>";
                    echo $u['profile_pic'] ? "<img src='" . htmlspecialchars($u['profile_pic']) . "' class='profile-pic'>" : "<img src='" . getDefaultProfilePic($u['username']) . "' class='profile-pic'>";
                    echo "</td>";
                    echo "<td>" . htmlspecialchars($u['username']) . " " . getBadge($u['admin_level']) . "</td>";
                    echo "<td>";
                    if ($u['admin_level'] == 0) echo "User";
                    if ($u['admin_level'] == 1) echo "MOD";
                    if ($u['admin_level'] == 2) echo "ADMIN";
                    if ($u['admin_level'] == 3) echo "FOUNDER";
                    echo "</td>";
                    echo "<td>";
                    if ($u['banned']) echo "<span class='banned-label'>BANNED</span>";
                    else echo "Active";
                    echo "</td>";
                    echo "<td class='admin-actions'>
                        <form method='post' style='display:inline;'>
                            <input type='hidden' name='user_id' value='{$u['id']}'>
                            <select name='level'>
                                <option value='0' ".($u['admin_level']==0?'selected':'').">User</option>
                                <option value='1' ".($u['admin_level']==1?'selected':'').">MOD</option>
                                <option value='2' ".($u['admin_level']==2?'selected':'').">ADMIN</option>
                            </select>
                            <button name='promote_user'>Set</button>
                            <button name='delete_user' class='delete-btn' onclick=\"return confirm('Delete user?')\">Delete</button>";
                    if ($u['banned']) {
                        echo "<button name='unban_user' class='unban-btn'>Unban</button>";
                    } else {
                        echo "<button name='ban_user' class='ban-btn' onclick=\"return confirm('Ban user?')\">Ban</button>";
                    }
                    echo "<button name='reset_password' class='reset-btn' onclick=\"return confirm('Reset password?')\">Reset PW</button>";
                    echo "</form>
                    </td>";
                    echo "</tr>";
                }
                ?>
            </table>
        </div>
        <div class="admin-section">
            <h3>Forums</h3>
            <table class="admin-table">
                <tr>
                    <th>ID</th>
                    <th>Image</th>
                    <th>Title</th>
                    <th>Creator</th>
                    <th>Created At</th>
                    <th>Actions</th>
                </tr>
                <?php
                $forums = $pdo->query("SELECT * FROM forums")->fetchAll(PDO::FETCH_ASSOC);
                foreach ($forums as $f) {
                    $creator = getUserById($f['creator_id']);
                    echo "<tr>";
                    echo "<td>{$f['id']}</td>";
                    echo "<td>";
                    if ($f['image']) echo "<img src='" . htmlspecialchars($f['image']) . "' class='img-preview'>";
                    echo "</td>";
                    echo "<td>" . htmlspecialchars($f['title']) . "</td>";
                    echo "<td>" . htmlspecialchars($creator['username']) . "</td>";
                    echo "<td>{$f['created_at']}</td>";
                    echo "<td>
                        <a href='?delete_forum={$f['id']}&admin=1' class='delete-btn' onclick=\"return confirm('Delete forum?')\">Delete</a>
                    </td>";
                    echo "</tr>";
                }
                ?>
            </table>
        </div>
        <div class="admin-section">
            <h3>Comments</h3>
            <table class="admin-table">
                <tr>
                    <th>ID</th>
                    <th>Forum</th>
                    <th>User</th>
                    <th>Content</th>
                    <th>Image</th>
                    <th>Created At</th>
                    <th>Actions</th>
                </tr>
                <?php
                $comments = $pdo->query("SELECT * FROM comments")->fetchAll(PDO::FETCH_ASSOC);
                foreach ($comments as $c) {
                    $cu = getUserById($c['user_id']);
                    echo "<tr>";
                    echo "<td>{$c['id']}</td>";
                    echo "<td>{$c['forum_id']}</td>";
                    echo "<td>" . htmlspecialchars($cu['username']) . "</td>";
                    echo "<td>" . nl2br(htmlspecialchars($c['content'])) . "</td>";
                    echo "<td>";
                    if ($c['image']) echo "<img src='" . htmlspecialchars($c['image']) . "' class='img-preview'>";
                    echo "</td>";
                    echo "<td>{$c['created_at']}</td>";
                    echo "<td>
                        <a href='?delete_comment={$c['id']}&admin=1' class='delete-btn' onclick=\"return confirm('Delete comment?')\">Delete</a>
                    </td>";
                    echo "</tr>";
                }
                ?>
            </table>
        </div>
    </div>
    </body>
    </html>
    <?php
    exit;
}

// --- PAGE HEADER ---
?>
<!DOCTYPE html>
<html>
<head>
    <title>FFORUM</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(90deg, #0055a4 0%, #ffffff 50%, #ef4135 100%);
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 900px;
            margin: 48px auto;
            background: translucid;
            border-radius: 18px;
            box-shadow: 0 8px 36px rgba(0,0,0,0.13);
            padding: 40px 48px 48px 48px;
        }
        h1 {
            font-family: 'Montserrat', Arial, sans-serif;
            font-size: 2.8em;
            letter-spacing: 2px;
            color: #fff;
            text-align: center;
            margin-bottom: 18px;
            display: block;
            background: #111;
            border-radius: 32px;
            padding: 18px 54px;
            box-shadow: 0 2px 16px rgba(0,0,0,0.13);
            margin-left: auto;
            margin-right: auto;
            width: fit-content;
        }
        h2 {
            font-size: 1.5em;
            color:rgb(0, 0, 0);
            margin-bottom: 18px;
        }
        .forum {
            border: 1px solid #dfe6e9;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 22px;
            background: #f9fafb;
            transition: box-shadow 0.2s, border 0.2s;
            box-shadow: 0 2px 12px rgba(0,0,0,0.06);
        }
        .forum:hover {
            box-shadow: 0 4px 18px rgba(0,0,0,0.10);
            border: 1.5px solid #0984e3;
        }
        .comment {
            margin-left: 40px;
            border-left: 4px solid #b2bec3;
            padding-left: 18px;
            margin-bottom: 14px;
            background: #f1f2f6;
            border-radius: 8px;
            box-shadow: 0 1px 6px rgba(0,0,0,0.04);
        }
        .badge {
            font-weight: bold;
            padding: 2px 10px;
            border-radius: 8px;
            font-size: 1em;
            margin-left: 8px;
        }
        .badge-mod { background: #d6eaff; color: #0984e3; }
        .badge-admin { background: #ffe6e6; color: #d63031; }
        .badge-founder { background: #f3e6ff; color: #6c3483; }
        .img-preview {
            max-width: 120px;
            max-height: 120px;
            border-radius: 10px;
            margin: 4px 0 4px 10px;
            vertical-align: middle;
            box-shadow: 0 1px 6px rgba(0,0,0,0.07);
        }
        .profile-pic {
            width: 44px;
            height: 44px;
            border-radius: 50%;
            object-fit: cover;
            margin-right: 12px;
            vertical-align: middle;
            border: 2px solid #dfe6e9;
            box-shadow: 0 1px 6px rgba(0,0,0,0.06);
        }
        .user-block {
            display: flex;
            align-items: center;
            margin-bottom: 8px;
        }
        .form-inline input[type="text"], .form-inline input[type="password"] {
            padding: 9px 12px;
            border-radius: 6px;
            border: 1px solid #b2bec3;
            margin-right: 10px;
            font-size: 1em;
        }
        .form-inline button {
            padding: 9px 20px;
            border-radius: 6px;
            border: none;
            background: #0984e3;
            color: #fff;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.2s;
            font-size: 1em;
        }
        .form-inline button:hover {
            background: #74b9ff;
        }
        .form-group {
            margin-bottom: 14px;
        }
        .alert {
            padding: 12px 22px;
            border-radius: 8px;
            margin-bottom: 22px;
            font-size: 1.1em;
        }
        .alert-error { background: #ffe6e6; color: #d63031; }
        .alert-success { background: #eafaf1; color: #27ae60; }
        .profile-edit {
            background: #f1f2f6;
            border-radius: 10px;
            padding: 22px;
            margin-bottom: 22px;
            border: 1px solid #dfe6e9;
        }
        .profile-edit label { font-weight: bold; }
        .profile-edit input[type="file"] { margin-top: 10px; }
        .forum-image {
            display: block;
            margin: 10px 0 10px 0;
            max-width: 320px;
            max-height: 200px;
            border-radius: 10px;
            box-shadow: 0 1px 8px rgba(0,0,0,0.09);
        }
        .comment-image {
            display: block;
            margin: 8px 0 8px 0;
            max-width: 200px;
            max-height: 140px;
            border-radius: 8px;
            box-shadow: 0 1px 6px rgba(0,0,0,0.07);
        }
        .back-link {
            display: inline-block;
            margin-top: 22px;
            color: #636e72;
            text-decoration: none;
            font-size: 1.1em;
        }
        .back-link:hover { color: #0984e3; }
        .forum-title-link {
            color: #2d3436;
            text-decoration: none;
            font-size: 1.25em;
            font-weight: bold;
            margin-right: 5px;
        }
        .forum-title-link:hover { color: #0984e3; }
        .created-at {
            color: #636e72;
            font-size: 1em;
            margin-top: 6px;
        }
        .actions {
            margin-left: 12px;
        }
        .delete-link {
            color: #d63031;
            text-decoration: none;
            font-weight: bold;
            margin-left: 10px;
        }
        .delete-link:hover {
            color: #ff7675;
        }
        .banned-label {
            color: #d63031;
            font-weight: bold;
            margin-left: 8px;
        }
        @media (max-width: 700px) {
            .container { padding: 12px; }
            .forum-image, .comment-image { max-width: 98vw; }
        }
    </style>
</head>
<body>
<div class="container">
<h1><span style="color: blue;">FF</span><span style="color: white;">OR</span><span style="color: red;">UM</span></h1>
<?php
if (isset($error)) echo "<div class='alert alert-error'>" . htmlspecialchars($error) . "</div>";
if (isset($success)) echo "<div class='alert alert-success'>" . $success . "</div>";

if (isLoggedIn()) {
    $u = getUser();
    $profilePic = $u['profile_pic'] ?: getDefaultProfilePic($u['username']);
    echo "<div class='user-block'>";
    echo "<img src='" . htmlspecialchars($profilePic) . "' class='profile-pic'>";
    echo "<span>Logged in as <b>" . htmlspecialchars($u['username']) . "</b> " . getBadge($u['admin_level']);
    if (isset($u['banned']) && $u['banned']) echo " <span class='banned-label'>(BANNED)</span>";
    echo "</span>";
    echo " <span class='actions'>| <a href='?logout=1'>Logout</a>";
    if (isFounder()) echo " | <a href='?admin=1'>Admin Dashboard</a>";
    echo "</span></div><hr>";

    // Profile edit form
    ?>
    <div class="profile-edit">
        <form method="post" enctype="multipart/form-data">
            <label>Change profile picture (JPG, PNG, GIF):</label><br>
            <input type="file" name="profile_pic" accept="image/jpeg,image/png,image/gif">
            <button name="edit_profile">Update Profile</button>
        </form>
    </div>
    <?php

    // Forum creation form
    ?>
    <form method="post" enctype="multipart/form-data" class="form-inline">
        <input type="text" name="title" placeholder="Forum title" required>
        <input type="file" name="forum_image" accept="image/jpeg,image/png,image/gif">
        <button name="create_forum">Create Forum</button>
    </form>
    <hr>
    <?php
} else {
    // Register/Login forms
    ?>
    <form method="post" enctype="multipart/form-data" style="display:inline-block;">
        <h3>Register</h3>
        <div class="form-group">
            <input type="text" name="username" placeholder="Username" maxlength="32" required pattern="[a-zA-Z0-9_-]{1,32}" title="1-32 letters, numbers, - or _">
        </div>
        <div class="form-group">
            <label>Profile picture (optional):</label>
            <input type="file" name="profile_pic" accept="image/jpeg,image/png,image/gif">
        </div>
        <button name="register">Register</button>
    </form>
    <form method="post" style="display:inline-block; margin-left:30px;">
        <h3>Login</h3>
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button name="login">Login</button>
    </form>
    <hr>
    <?php
}

// --- FORUM LIST OR FORUM VIEW ---
$pdo = getPDO();
if (isset($_GET['forum'])) {
    $forumId = (int)$_GET['forum'];
    $stmt = $pdo->prepare("SELECT * FROM forums WHERE id=?");
    $stmt->execute([$forumId]);
    $forum = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($forum) {
        $creator = getUserById($forum['creator_id']);
        $creatorPic = $creator['profile_pic'] ?: getDefaultProfilePic($creator['username']);
        echo "<div class='forum'>";
        echo "<div class='user-block'>";
        echo "<img src='" . htmlspecialchars($creatorPic) . "' class='profile-pic'>";
        echo "<span><b>" . htmlspecialchars($forum['title']) . "</b> by " . htmlspecialchars($creator['username']) . " " . getBadge($creator['admin_level']) . "</span>";
        if (isLoggedIn() && ($forum['creator_id'] == getUser()['id'] || isAdmin() || isFounder())) {
            echo " <a href='?delete_forum={$forum['id']}' class='delete-link' onclick=\"return confirm('Delete forum?')\">Delete</a>";
        }
        echo "</div>";
        if ($forum['image']) echo "<img src='" . htmlspecialchars($forum['image']) . "' class='forum-image'>";
        echo "<div class='created-at'>Created at: {$forum['created_at']}</div></div>";

        // Comments
        $stmt = $pdo->prepare("SELECT * FROM comments WHERE forum_id=? ORDER BY created_at ASC");
        $stmt->execute([$forumId]);
        $comments = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo "<h3>Comments</h3>";
        foreach ($comments as $c) {
            $cu = getUserById($c['user_id']);
            $cuPic = $cu['profile_pic'] ?: getDefaultProfilePic($cu['username']);
            echo "<div class='comment'>";
            echo "<div class='user-block'>";
            echo "<img src='" . htmlspecialchars($cuPic) . "' class='profile-pic'>";
            echo "<span><b>" . htmlspecialchars($cu['username']) . "</b> " . getBadge($cu['admin_level']);
            if ($cu['banned']) echo " <span class='banned-label'>(BANNED)</span>";
            echo ": " . nl2br(htmlspecialchars($c['content'])) . "</span>";
            if (isLoggedIn() && (
                $c['user_id'] == getUser()['id'] ||
                isAdmin() || isFounder() || isMod() ||
                $forum['creator_id'] == getUser()['id']
            )) {
                echo " <a href='?delete_comment={$c['id']}&forum=$forumId' class='delete-link' onclick=\"return confirm('Delete comment?')\">Delete</a>";
            }
            echo "</div>";
            if ($c['image']) echo "<img src='" . htmlspecialchars($c['image']) . "' class='comment-image'>";
            echo "<div class='created-at'>{$c['created_at']}</div>";
            echo "</div>";
        }
        // Add comment form
        if (isLoggedIn()) {
            ?>
            <form method="post" enctype="multipart/form-data" class="form-inline">
                <input type="hidden" name="forum_id" value="<?php echo $forumId; ?>">
                <input type="text" name="content" placeholder="Add a comment..." required>
                <input type="file" name="comment_image" accept="image/jpeg,image/png,image/gif">
                <button name="add_comment">Comment</button>
            </form>
            <?php
        }
        echo "<a href='index.php' class='back-link'>&larr; Back to forums</a>";
    } else {
        echo "Forum not found. <a href='index.php' class='back-link'>Back</a>";
    }
} else {
    // List forums
    $forums = $pdo->query("SELECT * FROM forums ORDER BY created_at DESC")->fetchAll(PDO::FETCH_ASSOC);
    echo "<h2>Forums</h2>";
    foreach ($forums as $f) {
        $creator = getUserById($f['creator_id']);
        $creatorPic = $creator['profile_pic'] ?: getDefaultProfilePic($creator['username']);
        echo "<div class='forum'>";
        echo "<div class='user-block'>";
        echo "<img src='" . htmlspecialchars($creatorPic) . "' class='profile-pic'>";
        echo "<a href='?forum={$f['id']}' class='forum-title-link'>" . htmlspecialchars($f['title']) . "</a> by " . htmlspecialchars($creator['username']) . " " . getBadge($creator['admin_level']);
        if (isset($creator['banned']) && $creator['banned']) echo " <span class='banned-label'>(BANNED)</span>";
        if (isLoggedIn() && ($f['creator_id'] == getUser()['id'] || isAdmin() || isFounder())) {
            echo " <a href='?delete_forum={$f['id']}' class='delete-link' onclick=\"return confirm('Delete forum?')\">Delete</a>";
        }
        echo "</div>";
        if ($f['image']) echo "<img src='" . htmlspecialchars($f['image']) . "' class='forum-image'>";
        echo "<div class='created-at'>Created at: {$f['created_at']}</div>";
        echo "</div>";
    }
}
?>
</div>
</body>
</html>