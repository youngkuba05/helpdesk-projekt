# LAB6 — bezpieczeństwo CI/CD

Konfiguracja: [ci-cd.yml](../.github/workflows/ci-cd.yml). Zmiany są sprawdzane
na pull requestach do `main`, gałęzi `lab6-security` i gałęziach `lab6/**`.
Wdrożenie AWS uruchamia się wyłącznie na `main`, poza pull requestami.

## Przepływ

1. Testy aplikacji, SAST (Bandit), SCA (pip-audit) i skan sekretów (Gitleaks).
2. Jednorazowa budowa obrazu `linux/amd64`, skan Trivy oraz ZAP Baseline
   przeciwko temu obrazowi uruchomionemu z tymczasową bazą SQLite.
3. `Security gate` wymaga sukcesu wszystkich pięciu zadań. Niepowodzenie,
   pominięcie lub anulowanie kontroli blokuje wdrożenie.
4. Na `main` obraz przechodzi między zadaniami jako artefakt tego samego
   uruchomienia. Sprawdzane są suma SHA256 archiwum i identyfikator obrazu.
   Wdrożenie nie buduje obrazu ponownie.
5. Obraz trafia do ECR. Cosign podpisuje jego digest i weryfikuje podpis
   z dokładną tożsamością tego workflow na `main` oraz issuerem GitHub Actions.
   ECS otrzymuje ten sam adres `repo@sha256:…`.

Cosign korzysta z tokenu GitHuba do Sigstore; nie wymaga prywatnego klucza
w sekretach repozytorium ani dostawcy OIDC w AWS. Dostęp do AWS nadal używa
dotychczasowych sekretów IAM. Metadane podpisu trafiają do publicznego
dziennika Sigstore. Błąd podpisywania lub weryfikacji zatrzymuje wdrożenie.

## Co blokuje pipeline

- Bandit, pip-audit i Gitleaks: każde wykryte ustalenie lub błąd narzędzia.
- Trivy: każdy `CRITICAL`, także bez poprawki, oraz `HIGH` z dostępną poprawką.
  `HIGH` bez poprawki nie blokują tego laboratorium, ale pozostają w pełnym
  raporcie; taki obraz nadal zawiera znane podatności.
- ZAP: błąd skanera, niepoprawny raport, każde `HIGH` i nowe niezaakceptowane
  ostrzeżenie. Powrót brakujących nagłówków `10020`/`10021` również blokuje.

Znane ryzyka ZAP zaakceptowane dla zakresu LAB6: brak wymuszanego CSP (`10038`),
niepełna ochrona CSRF (`10202`), polityki izolacji między źródłami (`90004`)
oraz Permissions-Policy (`10063`). Wyjątki obejmują tylko znane ścieżki
określone w [check_scan_reports.py](../scripts/check_scan_reports.py).
Nie są to naprawione podatności. CSP `Report-Only` nie wymusza ochrony.
Ustalenia informacyjne pozostają widoczne i nie blokują.

DAST obejmuje publiczne strony bez logowania, przez lokalne HTTP.
Nie potwierdza bezpieczeństwa paneli po zalogowaniu ani konfiguracji TLS.
Pełne raporty Trivy/ZAP są artefaktami `security-image-and-dast` przez 7 dni.
Obraz do wdrożenia jest przechowywany przez 1 dzień.

## Sprawdzenie lokalne

Python 3.11, pakiety z `security/requirements.txt` i Gitleaks 8.30.1 na `PATH`:

```sh
python scripts/check_security_pipeline.py
python -m unittest discover -s scripts -p '*_test.py' -v
```

`TICKETDESK_TEST_SCA=1` włącza dodatkowy test z publiczną bazą podatności.
Testy podpisu, digestu i artefaktu wykonują fragmenty workflow z lokalnymi
atrapami narzędzi; nie łączą się z AWS i nie zastępują uruchomienia na GitHubie.
Lokalny Docker na Macu używa `linux/arm64`; wariant `amd64` sprawdza CI.

Po pushu trzeba potwierdzić wynik `Security gate`. Właściciel/administrator
repozytorium może ustawić go jako wymagany warunek połączenia PR z `main`.
Połączenie z ECR, uprawnienia IAM do podpisów i faktyczne wdrożenie wymagają
osobnego potwierdzenia podczas uruchomienia zadania `deploy`.
