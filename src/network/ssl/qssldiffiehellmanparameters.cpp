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


/*!
    \class QSslDiffieHellmanParameters
    \brief The QSslDiffieHellmanParameters class provides an interface for Diffie-Hellman parameters for servers.
    \since 5.7

    \reentrant
    \ingroup network
    \ingroup ssl
    \ingroup shared
    \inmodule QtNetwork

    QSslDiffieHellmanParameters provides an interface for setting Diffie-Hellman parameters to servers based on QSslSocket.

    \sa QSslSocket, QSslCipher, QSslConfiguration
*/

#include "qssldiffiehellmanparameters.h"
#include "qssldiffiehellmanparameters_p.h"
#include "qsslsocket.h"
#include "qsslsocket_p.h"

#include <QtCore/qatomic.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qbytearraymatcher.h>
#include <QtCore/qiodevice.h>
#ifndef QT_NO_DEBUG_STREAM
#include <QtCore/qdebug.h>
#endif

QT_BEGIN_NAMESPACE

/*!
    Returns the default QSslDiffieHellmanParameters used by QSslSocket.

    This is currently the 1024-bit MODP group from RFC 2459, also
    known as the Second Oakley Group.
*/
QSslDiffieHellmanParameters QSslDiffieHellmanParameters::defaultParameters()
{
    // The 1024-bit MODP group from RFC 2459 (Second Oakley Group)
    return QSslDiffieHellmanParameters(
        QByteArray::fromBase64(QByteArrayLiteral(
            "MIGHAoGBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJR"
            "Sgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL"
            "/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7OZTgf//////////AgEC"
        )),
        QSsl::Der
    );
}

/*!
    Constructs an empty QSslDiffieHellmanParameters instance.

    If an empty QSslDiffieHellmanParameters instance is set on a
    QSslConfiguration object, Diffie-Hellman negotiation will
    be disabled.

    \sa isValid()
    \sa QSslConfiguration
*/
QSslDiffieHellmanParameters::QSslDiffieHellmanParameters()
    : d(new QSslDiffieHellmanParametersPrivate)
{
}

/*!
    Constructs a QSslDiffieHellmanParameters object using
    the byte array \encoded in either PEM or DER form.

    After construction, the isValid() method should be used to
    check whether the Diffie-Hellman parameters were valid and
    loaded correctly.

    \sa isValid()
    \sa QSslConfiguration
*/
QSslDiffieHellmanParameters::QSslDiffieHellmanParameters(const QByteArray &encoded, QSsl::EncodingFormat encoding)
    : d(new QSslDiffieHellmanParametersPrivate)
{
    switch (encoding) {
        case QSsl::Der:
            d->decodeDer(encoded);
            break;
        case QSsl::Pem:
            d->decodePem(encoded);
            break;
    }
}

/*!
    Constructs a QSslDiffieHellmanParameters object by
    reading from \device in either PEM or DER form.

    After construction, the isValid() method should be used
    to check whether the Diffie-Hellman parameters were valid
    and loaded correctly.

    \sa isValid()
    \sa QSslConfiguration
*/
QSslDiffieHellmanParameters::QSslDiffieHellmanParameters(QIODevice *device, QSsl::EncodingFormat encoding)
    : d(new QSslDiffieHellmanParametersPrivate)
{
    if (!device)
        return;

    const QByteArray encoded = device->readAll();

    switch (encoding) {
        case QSsl::Der:
            d->decodeDer(encoded);
            break;
        case QSsl::Pem:
            d->decodePem(encoded);
            break;
    }
}

/*!
    Constructs an identical copy of \a other.
*/
QSslDiffieHellmanParameters::QSslDiffieHellmanParameters(const QSslDiffieHellmanParameters &other) : d(other.d)
{
}

/*!
    Destroys the QSslDiffieHellmanParameters object.
*/
QSslDiffieHellmanParameters::~QSslDiffieHellmanParameters()
{
}

/*!
    Copies the contents of \a other into this QSslDiffieHellmanParameters, making the two QSslDiffieHellmanParameters
    identical.

    Returns a reference to this QSslDiffieHellmanParameters.
*/
QSslDiffieHellmanParameters &QSslDiffieHellmanParameters::operator=(const QSslDiffieHellmanParameters &other)
{
    d = other.d;
    return *this;
}

/*!
    \fn QSslDiffieHellmanParameters &QSslDiffieHellmanParameters::operator=(QSslDiffieHellmanParameters &&other)

    Move-assigns \a other to this QSslDiffieHellmanParameters instance.
*/

/*!
    \fn void QSslDiffieHellmanParameters::swap(QSslDiffieHellmanParameters &other)

    Swaps this QSslDiffieHellmanParameters with \a other. This function is very fast and
    never fails.
*/

/*!
    Returns \c true if this is a an empty QSslDiffieHellmanParameters instance.

    Setting an empty QSslDiffieHellmanParameters instance on a QSslSocket-based
    server will disable Diffie-Hellman key exchange.
*/
bool QSslDiffieHellmanParameters::isEmpty() const
{
    return d->derData.isNull() && d->error == QSslDiffieHellmanParameters::NoError;
}

/*!
    Returns \c true if this is a valid QSslDiffieHellmanParameters; otherwise false.

    This method should be used after constructing a QSslDiffieHellmanParameters
    object to determine its validity.

    If a QSslDiffieHellmanParameters object is not valid, you can use the error()
    method to determine what error prevented the object from being constructed.

    \sa clear()
    \sa error()
*/
bool QSslDiffieHellmanParameters::isValid() const
{
    return d->error == QSslDiffieHellmanParameters::NoError;
}

/*!
    \enum QSslDiffieHellmanParameters::Error

    Describes a QSslDiffieHellmanParameters error.

    \value ErrorInvalidInputData The given input data could not be used to
                                 construct a QSslDiffieHellmanParameters
                                 object.

    \value ErrorUnsafeParameters The Diffie-Hellman parameters are unsafe
                                 and should not be used.
*/

/*!
    Returns the error that caused the QSslDiffieHellmanParameters object
    to be invalid.
*/
QSslDiffieHellmanParameters::Error QSslDiffieHellmanParameters::error() const
{
    return d->error;
}

/*!
    Returns a human-readable description of the error that caused the
    QSslDiffieHellmanParameters object to be invalid.
*/
QString QSslDiffieHellmanParameters::errorString() const
{
    switch (d->error) {
        case QSslDiffieHellmanParameters::NoError:
            return tr("no error");
        case QSslDiffieHellmanParameters::InvalidInputDataError:
            return tr("invalid input data");
        case QSslDiffieHellmanParameters::UnsafeParametersError:
            return tr("the given Diffie-Hellman parameters are deemed unsafe");
    }
}

/*!
    \relates QSslDiffieHellmanParameters

    Returns \c true if \a lhs is equal to \a rhs; otherwise returns \c false.
*/
bool operator==(const QSslDiffieHellmanParameters &lhs, const QSslDiffieHellmanParameters &rhs) Q_DECL_NOTHROW
{
    return lhs.d->derData == rhs.d->derData;
}

/*! \fn bool QSslDiffieHellmanParameters::operator!=(const QSslDiffieHellmanParameters &other) const

  Returns \c true if this QSslDiffieHellmanParameters is not equal to \a other; otherwise
  returns \c false.
*/

#ifndef QT_NO_DEBUG_STREAM
/*!
    \relates QSslDiffieHellmanParameters

    Writes the set of Diffie-Hellman parameters in \a dhparm into the debug object \a debug for
    debugging purposes.

    The Diffie-Hellman parameters will be represented in Base64-encoded DER form.

    \sa {Debugging Techniques}
*/
QDebug operator<<(QDebug debug, const QSslDiffieHellmanParameters &dhparam)
{
    QDebugStateSaver saver(debug);
    debug.resetFormat().nospace();
    debug << "QSslDiffieHellmanParameters(" << dhparam.d->derData.toBase64() << ')';
    return debug;
}
#endif

/*!
    \relates QHash

    Returns an hash value for \a dhparam, using \a seed to seed
    the calculation.
*/
uint qHash(const QSslDiffieHellmanParameters &dhparam, uint seed) Q_DECL_NOTHROW
{
    return qHash(dhparam.d->derData, seed);
}

QT_END_NAMESPACE
