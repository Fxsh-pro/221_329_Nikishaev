#include "mainwindow.h"
#include <QRandomGenerator>
#include <QMessageBox>
#include <QBuffer>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonObject>
#include <QJsonDocument>
#include <QJsonArray>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {

    ui->setupUi(this);
    ui->stackedWidget->setCurrentWidget(ui->mainPage);

    connect(ui->uploadFileButton, &QPushButton::clicked, this, &MainWindow::openFile);
    loadPincode();
    qDebug() << "PINCODE  " + pincode;
    loadTransactions();
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::loadPincode() {
    QString pincodeFilePath = "D:/educ-2c2s-cryptographic/exam/pincode.txt";
    QFile file(pincodeFilePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Could not open pincode file");
        return;
    }

    QTextStream in(&file);
    if (!in.atEnd()) {
        pincode = in.readLine().trimmed();
    } else {
        QMessageBox::critical(this, "Error", "Pincode file is empty");
    }

    file.close();
}

QByteArray MainWindow::calculateHash(const Transaction &transaction, const QByteArray &previousHash) {
    QString concatenatedString = transaction.amount + transaction.walletNumber + transaction.date + QString(previousHash.toHex());
    QByteArray data = concatenatedString.toUtf8();
    auto hash = QCryptographicHash::hash(data, QCryptographicHash::Sha256);
    QString readableHash = QString::fromUtf8(hash.toHex());
    qDebug() << "transaction:" << concatenatedString;
    qDebug() << "previousHash:" << previousHash.toHex();
    qDebug() << "Hash for transaction:" << readableHash;
    return hash;
}

void MainWindow::displayTransactions(const QVector<Transaction> &transactions) {
    QByteArray previousHash;
    bool hashMismatch = false;

    ui->transactionsList->clear();

    QString headerText = "Сумма, Номер кошелька, Дата, Хэш\n";

    QTextCursor cursor(ui->transactionsList->textCursor());
    cursor.movePosition(QTextCursor::End);
    QTextCharFormat headerFormat;
    cursor.insertText(headerText, headerFormat);

    for (const Transaction &transaction : transactions) {
        QByteArray calculatedHash = calculateHash(transaction, previousHash);
        bool hashesMatch = (calculatedHash == transaction.hash);

        QString displayText = QString("%1, %2, %3, %4\n")
                                  .arg(transaction.amount, transaction.walletNumber, transaction.date, transaction.hash.toHex());

        QTextCharFormat format;
        if (!hashesMatch || hashMismatch) {
            format.setForeground(Qt::red);
            hashMismatch = true;
        }

        cursor.insertText(displayText, format);

        previousHash = transaction.hash;
    }
}

void MainWindow::openFile() {
    QString fileName = QFileDialog::getOpenFileName(this, tr("Открыть файл"), QString(), tr("Encrypted Files (*.enc)"));

    if (!fileName.isEmpty()) {
        filePath = fileName;
        loadPincode();
        loadTransactions();
    }
}

void MainWindow::loadTransactions() {

    QFile file(filePath);
    QByteArray decryptedData = decryptFile(filePath, pincode);
    qDebug() << decryptedData;
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Error", "Could not open transactions file");
        return;
    }

    QTextStream in(&decryptedData);
    QVector<Transaction> transactions;
    while (!in.atEnd()) {
        QString line = in.readLine();
        QStringList fields = line.split(',');

        if (fields.size() != 4) {
            continue;
        }

        Transaction transaction;
        transaction.amount = fields[0];
        transaction.walletNumber = fields[1];
        transaction.date = fields[2];
        transaction.hash = QByteArray::fromHex(fields[3].toUtf8());

        transactions.append(transaction);
    }

    displayTransactions(transactions);
}

QByteArray MainWindow::decryptFile(const QString &filePath, const QString &key)
{
    iv = QByteArray::fromHex("17e8e506e37fd4d63c2cfb6b85f8cfc2");

    if (key.isEmpty() || key.length() != 64) {
        QMessageBox::warning(this, "Ошибка", "Неверный ключ для расшифровки. Длина ключа должна быть 64 символа.");
        return QByteArray();
    }

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        QMessageBox::warning(this, "Ошибка", "Не удалось открыть файл для чтения.");
        return QByteArray();
    }

    QByteArray rowData = file.readAll();
    file.close();

    AES_KEY decryptKey;
    QByteArray keyBytes = QByteArray::fromHex(key.toUtf8());
    if (AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(keyBytes.constData()), 256, &decryptKey) < 0) {
        QMessageBox::warning(this, "Ошибка", "Не удалось установить ключ для расшифровки.");
        return QByteArray();
    }

    QByteArray decryptedData(rowData.size(), 0);
    AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(rowData.constData()),
                    reinterpret_cast<unsigned char*>(decryptedData.data()),
                    rowData.size(),
                    &decryptKey,
                    reinterpret_cast<unsigned char*>(iv.data()),
                    AES_DECRYPT);

    int paddingLength = decryptedData.at(decryptedData.size() - 1);
    decryptedData.chop(paddingLength);

    return decryptedData;
}
