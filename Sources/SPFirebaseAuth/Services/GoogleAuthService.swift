// The MIT License (MIT)
// Copyright © 2022 Ivan Vorobei (hello@ivanvorobei.io)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import UIKit
import GoogleSignIn
import Firebase

class GoogleAuthService: NSObject {
    
    static func signIn(on viewController: UIViewController, completion: ((SPFirebaseAuthData?) -> Void)?) {
        guard let clientID = FirebaseApp.app()?.options.clientID else { return }
        
        // Создание конфигурации Google Sign In
        let config = GIDConfiguration(clientID: clientID)
        
        // Настройка экземпляра GIDSignIn с нашей конфигурацией
        GIDSignIn.sharedInstance.configuration = config
        
        // Запуск процесса авторизации
        GIDSignIn.sharedInstance.signIn(withPresenting: viewController) { signInResult, error in
            guard error == nil else { completion?(nil); return }
            guard let user = signInResult?.user,
                  let idToken = user.idToken?.tokenString else {
                completion?(nil)
                return
            }
            
            let accessToken = user.accessToken.tokenString
            let data = SPFirebaseAuthData(token: idToken, accessToken: accessToken)
            completion?(data)
        }
    }
}
