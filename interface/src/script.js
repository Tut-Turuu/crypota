async function connect() {
    const btn = document.querySelector('#loginScreen button');
    const originalText = btn.textContent;
    
    btn.textContent = 'Подключение...';
    btn.disabled = true;

    try {
        const response = await connect_to_server('{"host": "localhost", "port": 5000}');
        
        console.log('Ответ от C++:', response);
        console.log('Тип ответа:', typeof response);
        
        const result = typeof response === 'string' ? JSON.parse(response) : response;

        if (result.status === 'ok') {
            document.getElementById('loginScreen').style.display = 'none';
            document.getElementById('app').style.display = 'flex';
            renderChatList();
        } else {
            alert('Ошибка подключения: ' + (result.message || 'Неизвестная ошибка'));
            btn.textContent = originalText;
            btn.disabled = false;
        }
    } catch (error) {
        console.error('JS Error:', error);
        alert('Произошла ошибка: ' + error.message);
        btn.textContent = originalText;
        btn.disabled = false;
    }
}

// чат

const chats = [
    { id: 1, name: 'чат 1', messages: [] }
];

let currentChatId = null;

function renderChatList() {
    const chatList = document.getElementById('chatList');
    chatList.innerHTML = '';
    
    chats.forEach(chat => {
        const lastMsg = chat.messages.length > 0 
            ? chat.messages[chat.messages.length - 1].text 
            : 'Нет сообщений';
        
        const chatItem = document.createElement('div');
        chatItem.className = 'chat-item' + (chat.id === currentChatId ? ' active' : '');
        chatItem.innerHTML = `
            <div class="chat-item-name">${chat.name}</div>
            <div class="chat-item-preview">${lastMsg}</div>
        `;
        chatItem.onclick = () => selectChat(chat.id);
        chatList.appendChild(chatItem);
    });
}

function selectChat(chatId) {
    currentChatId = chatId;
    const chat = chats.find(c => c.id === chatId);
    document.getElementById('chatHeader').textContent = chat.name;
    renderMessages();
    renderChatList();
}

function renderMessages() {
    const chatDiv = document.getElementById('chat');
    chatDiv.innerHTML = '';
    if (!currentChatId) return;
    
    const chat = chats.find(c => c.id === currentChatId);
    chat.messages.forEach(msg => {
        const msgDiv = document.createElement('div');
        msgDiv.className = 'msg ' + msg.type;
        msgDiv.textContent = msg.text;
        chatDiv.appendChild(msgDiv);
    });
    chatDiv.scrollTop = chatDiv.scrollHeight;
}

function send() {
    const input = document.getElementById('msgInput');
    const text = input.value;
    
    if (text.trim() && currentChatId) {
        const chat = chats.find(c => c.id === currentChatId);
        chat.messages.push({ type: 'out', text: text });
        
        // здесь потом будет вызов с++ чтоб отправка шифросообщения
        
        renderMessages();
        renderChatList();
        input.value = '';
    }
}