#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMap>
#include <QVector>
#include <QFile>
#include <QFileDialog>
#include "ui_mainwindow.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

struct Transaction {
    QString amount;
    QString walletNumber;
    QString date;
    QByteArray hash;
};

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void loadTransactions();
    void openFile();
    void loadPincode();

private:
    Ui::MainWindow *ui;
    QString filePath = "D:/educ-2c2s-cryptographic/exam/1.enc";
    QString pincode;

    QByteArray calculateHash(const Transaction &transaction, const QByteArray &previousHash);
    void displayTransactions(const QVector<Transaction> &transactions);
    QByteArray iv;

    QByteArray decryptFile(const QString &filePath, const QString &key);

    int decryptQByteArray(const QByteArray& encryptedBytes, QByteArray& decryptedBytes, unsigned char *key);
    int encryptQByteArray(const QByteArray &plainBytes, QByteArray &encryptedBytes, unsigned char *key);
};

#endif // MAINWINDOW_H
