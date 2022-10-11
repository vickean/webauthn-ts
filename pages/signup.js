// FE UI Mumbo Jumbo

function getCookie(name) {
    function escape(s) {
        return s.replace(/([.*+?\^$(){}|\[\]\/\\])/g, '\\$1')
    }
    const match = document.cookie.match(
        RegExp('(?:^|;\\s*)' + escape(name) + '=([^;]*)')
    )
    return match ? match[1] : null
}

function clearCookies() {
    const cookies = document.cookie.split(';')
    for (let i = 0; i < cookies.length; i++) {
        const spcook = cookies[i].split('=')
        deleteCookie(spcook[0])
    }
    function deleteCookie(cookiename) {
        const d = new Date()
        d.setDate(d.getDate() - 1)
        const expires = ';expires=' + d
        const name = cookiename
        const value = ''
        document.cookie = name + '=' + value + expires + '; path=/'
    }
    window.location = '' // TO REFRESH THE PAGE
}

function checkIfUserRegistered() {
    // const userId = getCookie('userId')
    const userName = getCookie('userName')
    // return !!userId && !!userName
    return !!userName
}

window.addEventListener('load', (event) => {
    if (checkIfUserRegistered()) {
        const userName = getCookie('userName')
        document.getElementById('login_flow').classList.remove('hidden')
        document.getElementById('register_flow').classList.add('hidden')
        document.getElementById('login_text').innerHTML = 'Hi ' + userName + ','
    }
})

function validateForm() {
    if (
        document.getElementById('uname').value !== '' &&
        document.getElementById('password').value !== '' &&
        document.getElementById('password').value.length == 6
    )
        document.getElementById('btn').removeAttribute('disabled')
    else document.getElementById('btn').setAttribute('disabled', 'true')
}

function validateLoginForm() {
    if (document.getElementById('login_uname').value !== '')
        document.getElementById('login').removeAttribute('disabled')
    else document.getElementById('login').setAttribute('disabled', 'true')
}

function loadLogin() {
    document.getElementById('btn').innerHTML = 'Loading...'
    document.getElementById('btn').classList.add('bg-green-600')
    const form = document.getElementsByClassName('form')[0]
    form.innerHTML =
        '<div class="mb-4"><p>Your key has been successfully registered.</p></div>'
    window.setTimeout(() => {
        form.innerHTML =
            '<div class="mb-4"><p>Your key has been successfully registered.</p><p>You are now logged in.</p><div class="flex items-center justify-center mt-2"><button class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" onclick="clearCookies()">Clear Session</button></div></div>'
    }, 1500)
}

function disableBtn() {
    const btns = document.getElementsByTagName('button')
    Array.from(btns).forEach((btn) => btn.setAttribute('disabled', 'true'))
}

function verifyLogin() {
    let form = document.getElementsByClassName('form')[0]
    form.innerHTML =
        '<div class="mb-4"><p>You are now logged in.</p><div class="flex items-center justify-center mt-2"><button class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline" onclick="clearCookies()">Clear Session</button></div></div>'
}
