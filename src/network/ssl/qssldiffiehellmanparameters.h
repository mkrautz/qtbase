/****************************************************************************
**
** Copyright (C) 2015 Mikkel Krautz <mikkel@krautz.dk>
** Contact: http://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL21$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see http://www.qt.io/terms-conditions. For further
** information use the contact form at http://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 2.1 or version 3 as published by the Free
** Software Foundation and appearing in the file LICENSE.LGPLv21 and
** LICENSE.LGPLv3 included in the packaging of this file. Please review the
** following information to ensure the GNU Lesser General Public License
** requirements will be met: https://www.gnu.org/licenses/lgpl.html and
** http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
** As a special exception, The Qt Company gives you certain additional
** rights. These rights are described in The Qt Company LGPL Exception
** version 1.1, included in the file LGPL_EXCEPTION.txt in this package.
**
** $QT_END_LICENSE$
**
****************************************************************************/


#ifndef QSSLDIFFIEHELLMANPARAMETERS_H
#define QSSLDIFFIEHELLMANPARAMETERS_H

#include <QtNetwork/qssl.h>
#include <QtCore/qnamespace.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qshareddata.h>

QT_BEGIN_NAMESPACE

#ifndef QT_NO_SSL

class QIODevice;
class QSslContext;
class QSslDiffieHellmanParametersPrivate;

class QSslDiffieHellmanParameters;
// qHash is a friend, but we can't use default arguments for friends (§8.3.6.4)
Q_NETWORK_EXPORT uint qHash(const QSslDiffieHellmanParameters &dhparam, uint seed = 0) Q_DECL_NOTHROW;

#ifndef QT_NO_DEBUG_STREAM
class QDebug;
Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, const QSslDiffieHellmanParameters &dhparams);
#endif

Q_NETWORK_EXPORT bool operator==(const QSslDiffieHellmanParameters &lhs, const QSslDiffieHellmanParameters &rhs) Q_DECL_NOTHROW;

inline bool operator!=(const QSslDiffieHellmanParameters &lhs, const QSslDiffieHellmanParameters &rhs) Q_DECL_NOTHROW
{
    return !operator==(lhs, rhs);
}

class QSslDiffieHellmanParameters
{
public:
    enum Error {
        NoError,
        InvalidInputDataError,
        UnsafeParametersError
    };

    Q_NETWORK_EXPORT static QSslDiffieHellmanParameters defaultParameters();

    Q_NETWORK_EXPORT QSslDiffieHellmanParameters();
    Q_NETWORK_EXPORT explicit QSslDiffieHellmanParameters(const QByteArray &encoded, QSsl::EncodingFormat format = QSsl::Pem);
    Q_NETWORK_EXPORT explicit QSslDiffieHellmanParameters(QIODevice *device, QSsl::EncodingFormat format = QSsl::Pem);
    Q_NETWORK_EXPORT QSslDiffieHellmanParameters(const QSslDiffieHellmanParameters &other);
    Q_NETWORK_EXPORT ~QSslDiffieHellmanParameters();
    Q_NETWORK_EXPORT QSslDiffieHellmanParameters &operator=(const QSslDiffieHellmanParameters &other);
#ifdef Q_COMPILER_RVALUE_REFS
    QSslDiffieHellmanParameters &operator=(QSslDiffieHellmanParameters &&other) Q_DECL_NOTHROW { swap(other); return *this; }
#endif

    void swap(QSslDiffieHellmanParameters &other) Q_DECL_NOTHROW { qSwap(d, other.d); }

    Q_NETWORK_EXPORT bool isEmpty() const Q_DECL_NOTHROW;
    Q_NETWORK_EXPORT bool isValid() const Q_DECL_NOTHROW;
    Q_NETWORK_EXPORT QSslDiffieHellmanParameters::Error error() const Q_DECL_NOTHROW;
    Q_NETWORK_EXPORT QString errorString() const Q_DECL_NOTHROW;

private:
    QExplicitlySharedDataPointer<QSslDiffieHellmanParametersPrivate> d;
    friend class QSslContext;
    friend Q_NETWORK_EXPORT bool operator==(const QSslDiffieHellmanParameters &lhs, const QSslDiffieHellmanParameters &rhs) Q_DECL_NOTHROW;
#ifndef QT_NO_DEBUG_STREAM
    friend Q_NETWORK_EXPORT QDebug operator<<(QDebug debug, const QSslDiffieHellmanParameters &dhparam);
#endif
    friend Q_NETWORK_EXPORT uint qHash(const QSslDiffieHellmanParameters &dhparam, uint seed) Q_DECL_NOTHROW;
};

Q_DECLARE_SHARED(QSslDiffieHellmanParameters)

#endif // QT_NO_SSL

QT_END_NAMESPACE

#endif
