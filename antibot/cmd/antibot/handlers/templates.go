package handlers

// botCheckHTMLTemplate — HTML/JS страница JavaScript challenge.
// Подставляется через fmt.Sprintf: единственный %s — JSON payload (ctx) для клиента.
// %% экранирует литеральные символы процента в CSS.
const botCheckHTMLTemplate = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Подтверждение</title>
    <style>
      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        margin: 0;
        background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
        color: #333;
      }
      .container {
        background: white;
        padding: 40px;
        border-radius: 12px;
        box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        max-width: 500px;
        width: 90%%;
        text-align: center;
      }
      h1 {
        margin: 0 0 30px 0;
        color: #333;
        font-size: 24px;
        font-weight: 600;
      }
      .captcha-container {
        margin: 30px 0;
        padding: 20px;
        background: #f8f9fa;
        border-radius: 8px;
        border: 2px solid #e9ecef;
        display: none; /* По умолчанию скрыта, показывается только если needCaptcha = true */
      }
      .captcha-container.visible {
        display: block;
      }
      .captcha-checkbox {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 12px;
        cursor: pointer;
        user-select: none;
      }
      .captcha-checkbox input[type="checkbox"] {
        width: 24px;
        height: 24px;
        cursor: pointer;
        accent-color: #667eea;
      }
      .captcha-checkbox label {
        font-size: 16px;
        color: #495057;
        cursor: pointer;
        margin: 0;
      }
      .loading {
        display: none;
        margin-top: 20px;
        color: #6c757d;
        font-size: 14px;
      }
      .error {
        display: none;
        margin-top: 20px;
        color: #dc3545;
        font-size: 14px;
        padding: 10px;
        background: #f8d7da;
        border-radius: 4px;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>Проверка безопасности</h1>
      <div class="captcha-container">
        <div class="captcha-checkbox">
          <input type="checkbox" id="humanCheckbox" onchange="handleCheckboxChange()">
          <label for="humanCheckbox">Подтвердите, что вы человек</label>
        </div>
      </div>
      <div class="loading" id="loading">Проверка...</div>
      <div class="error" id="error"></div>
    </div>
    <script>
      const ctx = %s;
      let captchaVerified = !ctx.needCaptcha; // Если капча не нужна, считаем её уже подтвержденной
      let needCaptcha = ctx.needCaptcha;

      // Проверяем доступность crypto.subtle при загрузке страницы
      if (!window.crypto || !window.crypto.subtle) {
        const error = document.getElementById('error');
        error.textContent = 'Ошибка: crypto.subtle недоступен. Требуется HTTPS соединение.';
        error.style.display = 'block';
        console.error('crypto.subtle is not available');
      }

      // Показываем капчу только если она нужна
      if (needCaptcha) {
        document.querySelector('.captcha-container').classList.add('visible');
      } else {
        // Если капча не нужна, сразу запускаем JavaScript challenge
        // Скрываем контейнер с капчей полностью
        document.querySelector('.captcha-container').style.display = 'none';
        // Показываем сообщение о проверке
        document.getElementById('loading').style.display = 'block';
        document.getElementById('loading').textContent = 'Выполняется проверка безопасности...';
        // Проверяем crypto.subtle перед запуском
        if (window.crypto && window.crypto.subtle) {
          startVerification();
        } else {
          const error = document.getElementById('error');
          error.textContent = 'Ошибка: требуется HTTPS соединение для проверки безопасности.';
          error.style.display = 'block';
        }
      }
      let pageLoadTime = Date.now();
      let mouseMoveCount = 0;
      let mouseMoveData = [];
      let minWaitTime = 2000; // Минимальное время ожидания 2 секунды

      // Отслеживаем движение мыши для детекции человеческого поведения
      document.addEventListener('mousemove', function(e) {
        mouseMoveCount++;
        if (mouseMoveData.length < 10) {
          mouseMoveData.push({
            x: e.clientX,
            y: e.clientY,
            time: Date.now() - pageLoadTime
          });
        }
      });

      // Отслеживаем клики для детекции человеческого поведения
      let clickCount = 0;
      document.addEventListener('click', function() {
        clickCount++;
      });

      function handleCheckboxChange() {
        console.log('Checkbox changed');
        const checkbox = document.getElementById('humanCheckbox');
        if (!checkbox) {
          console.error('Checkbox not found');
          return;
        }

        if (checkbox.disabled) {
          console.log('Checkbox is disabled');
          return;
        }

        console.log('Checkbox checked:', checkbox.checked, 'needCaptcha:', needCaptcha);

        // Если капча не нужна, просто запускаем проверку
        if (!needCaptcha) {
          if (checkbox.checked) {
            captchaVerified = true;
            console.log('Starting verification (no captcha needed)');
            startVerification();
          }
          return;
        }

        // Если checkbox снят, просто сбрасываем флаг
        if (!checkbox.checked) {
          captchaVerified = false;
          console.log('Checkbox unchecked');
          return;
        }

        // Если checkbox отмечен, проверяем условия
        const timeSinceLoad = Date.now() - pageLoadTime;
        const error = document.getElementById('error');

        console.log('Time since load:', timeSinceLoad, 'minWaitTime:', minWaitTime);
        console.log('Mouse move count:', mouseMoveCount);

        // Проверяем минимальное время ожидания (только для капчи)
        if (timeSinceLoad < minWaitTime) {
          checkbox.checked = false;
          error.textContent = 'Пожалуйста, подождите немного перед подтверждением.';
          error.style.display = 'block';
          console.log('Too fast, waiting required');
          return;
        }

        // Проверяем признаки человеческого поведения (уменьшаем требования)
        if (mouseMoveCount < 1) {
          checkbox.checked = false;
          error.textContent = 'Пожалуйста, переместите мышь по странице.';
          error.style.display = 'block';
          console.log('Mouse movement required');
          return;
        }

        // Все проверки пройдены - запускаем проверку
        captchaVerified = true;
        error.style.display = 'none';
        checkbox.disabled = true; // Блокируем повторные клики

        console.log('All checks passed, starting verification');
        // Запускаем проверку после подтверждения капчи
        startVerification();
      }

      async function startVerification() {
        const loading = document.getElementById('loading');
        const error = document.getElementById('error');

        if (!captchaVerified) {
          console.log('Captcha not verified, skipping verification');
          return;
        }

        loading.style.display = 'block';
        error.style.display = 'none';

        try {
          console.log('Starting verification...');

          // Проверяем доступность crypto.subtle (требует HTTPS или localhost)
          if (!window.crypto || !window.crypto.subtle) {
            throw new Error('crypto.subtle недоступен. Требуется HTTPS соединение.');
          }

          // Детекция автоматизированных браузеров (Selenium, Playwright и т.д.)
          const botDetection = [];

        // Проверка на WebDriver флаги
        if (navigator.webdriver === true) {
          botDetection.push('webdriver:true');
        }

        // Проверка на отсутствие стандартных браузерных свойств
        if (navigator.plugins === undefined || navigator.plugins.length === 0) {
          botDetection.push('plugins:missing');
        }

        // Проверка на отсутствие языков
        if (!navigator.languages || navigator.languages.length === 0) {
          botDetection.push('languages:missing');
        }

        // Проверка на аномалии в permissions API
        if (navigator.permissions === undefined) {
          botDetection.push('permissions:missing');
        }

        // Проверка на отсутствие chrome объекта (для Chrome-based ботов)
        if (window.chrome === undefined && navigator.userAgent.includes('Chrome')) {
          botDetection.push('chrome:missing');
        }

        // Проверка на отсутствие стандартных свойств window
        if (window.outerHeight === 0 || window.outerWidth === 0) {
          botDetection.push('window:anomaly');
        }

        // Если обнаружены признаки бота, добавляем в fingerprint
        if (botDetection.length > 0) {
          // Боты с признаками автоматизации получат низкий score
        }

        // Собираем базовый fingerprint браузера
        const baseFp = [
          navigator.userAgent,
          screen.width + 'x' + screen.height,
          navigator.language,
          new Date().getTimezoneOffset(),
          'bot_detection:' + botDetection.join(',')
        ];

        // Добавляем расширенные методы детекции ботов
        const advancedFp = [];

        // Canvas fingerprinting - уникальный отпечаток на основе рендеринга canvas
        try {
          const canvas = document.createElement('canvas');
          const ctx2d = canvas.getContext('2d');
          ctx2d.textBaseline = 'top';
          ctx2d.font = '14px Arial';
          ctx2d.fillText('Antibot challenge', 2, 2);
          advancedFp.push('canvas:' + canvas.toDataURL().slice(0, 100));
        } catch (e) {
          advancedFp.push('canvas:error');
        }

        // WebGL fingerprinting - характеристики видеокарты и драйверов
        try {
          const gl = document.createElement('canvas').getContext('webgl');
          if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
              advancedFp.push('webgl-vendor:' + gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL));
              advancedFp.push('webgl-renderer:' + gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL).slice(0, 50));
            }
            advancedFp.push('webgl-version:' + gl.getParameter(gl.VERSION));
          }
        } catch (e) {
          advancedFp.push('webgl:error');
        }

        // AudioContext fingerprinting - уникальные характеристики аудио системы
        // Используем Promise для асинхронной обработки
        const audioFpPromise = new Promise((resolve) => {
          try {
            const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioCtx.createOscillator();
            const analyser = audioCtx.createAnalyser();
            const gainNode = audioCtx.createGain();
            const scriptProcessor = audioCtx.createScriptProcessor(4096, 1, 1);

            gainNode.gain.value = 0;
            oscillator.connect(analyser);
            analyser.connect(scriptProcessor);
            scriptProcessor.connect(gainNode);
            gainNode.connect(audioCtx.destination);

            let resolved = false;
            scriptProcessor.onaudioprocess = function(bins) {
              if (resolved) return;
              resolved = true;
              try {
                const output = new Float32Array(analyser.frequencyBinCount);
                analyser.getFloatFrequencyData(output);
                const hash = Array.from(output.slice(0, 20))
                  .map(v => Math.abs(Math.round(v)))
                  .join(',');
                oscillator.stop();
                audioCtx.close();
                resolve('audio:' + hash.slice(0, 50));
              } catch (e) {
                resolve('audio:error');
              }
            };

            oscillator.start(0);

            // Таймаут на случай, если обработчик не сработает
            setTimeout(() => {
              if (!resolved) {
                resolved = true;
                try {
                  oscillator.stop();
                  audioCtx.close();
                } catch (e) {}
                resolve('audio:timeout');
              }
            }, 200);
          } catch (e) {
            resolve('audio:error');
          }
        });

        // Ждем завершения AudioContext fingerprinting
        const audioFp = await audioFpPromise;
        advancedFp.push(audioFp);

        // Объединяем все компоненты fingerprint
        const fp = [...baseFp, ...advancedFp].join('|');

        // Вычисляем токен: SHA-256(fingerprint|secret)
        // Secret одноразовый (связан с nonce), поэтому безопасен
        const dataToHash = fp + '|' + ctx.secret;
        const enc = new TextEncoder().encode(dataToHash);
        const digest = await crypto.subtle.digest('SHA-256', enc);
        const token = Array.from(new Uint8Array(digest))
          .map(b => b.toString(16).padStart(2, '0')).join('');

        // Подписываем fingerprint для защиты от подделки
        // HMAC-SHA256(secret, fingerprint) - сервер проверит подпись
        const keyData = new TextEncoder().encode(ctx.secret);
        const key = await crypto.subtle.importKey(
          'raw',
          keyData,
          { name: 'HMAC', hash: 'SHA-256' },
          false,
          ['sign']
        );
        const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(fp));
        const fingerprintSignature = Array.from(new Uint8Array(signature))
          .map(b => b.toString(16).padStart(2, '0')).join('');

          // Собираем данные о человеческом поведении
          const timeToComplete = Date.now() - pageLoadTime;
          const humanBehaviorData = {
            timeToComplete: timeToComplete,
            mouseMoveCount: mouseMoveCount,
            clickCount: clickCount,
            mouseMovements: mouseMoveData.slice(0, 5) // Первые 5 движений
          };

          // Отправляем nonce, fingerprint, подпись fingerprint, токен и подтверждение капчи на сервер
          const response = await fetch('/bot-verify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              nonce: ctx.nonce,
              fingerprint: fp,
              fingerprintSignature: fingerprintSignature,
              token: token,
              captchaVerified: captchaVerified, // true если капча подтверждена или не нужна
              humanBehavior: needCaptcha ? humanBehaviorData : null // Поведение только если была капча
            })
          });

          if (response.ok) {
            // Успешная верификация - перенаправляем на исходный URL
            window.location.href = ctx.returnUrl || '/';
          } else {
            // Ошибка верификации
            const errorText = await response.text();
            loading.style.display = 'none';
            error.textContent = 'Ошибка проверки. Пожалуйста, попробуйте еще раз.';
            error.style.display = 'block';
            // Сбрасываем галочку для повторной попытки
            document.getElementById('humanCheckbox').checked = false;
            captchaVerified = false;
          }
        } catch (err) {
          console.error('Verification error:', err);
          loading.style.display = 'none';
          error.textContent = 'Произошла ошибка: ' +
            (err.message || 'Неизвестная ошибка') +
            '. Пожалуйста, обновите страницу.';
          error.style.display = 'block';
          const checkbox = document.getElementById('humanCheckbox');
          if (checkbox) {
            checkbox.checked = false;
            checkbox.disabled = false; // Разблокируем для повторной попытки
          }
          captchaVerified = false;
        }
      }
    </script>
    <noscript>
      <div class="container">
        <h1>Проверка безопасности</h1>
        <p>Для продолжения необходимо включить JavaScript в вашем браузере.</p>
      </div>
    </noscript>
  </body>
</html>`
