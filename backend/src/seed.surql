-- konta testowe, uruchomienie: cargo run -- seed

LET $test_users = ['anna.admin', 'marek.kierownik', 'ewa.kierownik', 'piotr.redaktor',
                   'kasia.redaktor', 'jan.czytelnik', 'ola.czytelnik'];
DELETE session WHERE user.username IN $test_users;
DELETE user WHERE username IN $test_users;
DELETE note WHERE author IN $test_users;

CREATE user CONTENT { username: 'anna.admin',      role: 'administrator', must_change_password: false,
    password_hash: crypto::argon2::generate('zielona-herbata-o-poranku') };
CREATE user CONTENT { username: 'marek.kierownik', role: 'kierownik',     must_change_password: false,
    password_hash: crypto::argon2::generate('stary dąb rośnie powoli') };
CREATE user CONTENT { username: 'ewa.kierownik',   role: 'kierownik',     must_change_password: false,
    password_hash: crypto::argon2::generate('niebieski-rower-na-moście') };
CREATE user CONTENT { username: 'piotr.redaktor',  role: 'redaktor',      must_change_password: false,
    password_hash: crypto::argon2::generate('kawa bez cukru proszę') };
CREATE user CONTENT { username: 'kasia.redaktor',  role: 'redaktor',      must_change_password: true,
    password_hash: crypto::argon2::generate('Tq7#mK2p!x9R'),
    one_time_expires_at: time::now() + duration::from::hours(settings:main.one_time_valid_hours) };
CREATE user CONTENT { username: 'jan.czytelnik',   role: 'czytelnik',     must_change_password: false,
    password_hash: crypto::argon2::generate('cicha-noc-nad-jeziorem') };
CREATE user CONTENT { username: 'ola.czytelnik',   role: 'czytelnik',     must_change_password: false, blocked: true,
    password_hash: crypto::argon2::generate('wiosna przychodzi w marcu') };

UPDATE user SET password_history = [password_hash], password_changed_at = time::now()
    WHERE username IN $test_users AND !must_change_password;

CREATE note CONTENT { text: 'Plan wydania na listopad',        author: 'piotr.redaktor',
    approved: true, approved_by: 'marek.kierownik' };
CREATE note CONTENT { text: 'Zasady publikacji komentarzy',    author: 'piotr.redaktor',
    approved: true, approved_by: 'ewa.kierownik' };
CREATE note CONTENT { text: 'Szkic: podsumowanie kwartału',    author: 'kasia.redaktor' };
