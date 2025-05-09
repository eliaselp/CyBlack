# Generated by Django 5.1.7 on 2025-05-03 22:07

import Lista_negra.storage_backends
import Lista_negra.validators
import django.core.validators
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('Administrador', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='URL_Maliciosa',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('protocolo', models.CharField(choices=[('HTTP', 'HTTP'), ('HTTPS', 'HTTPS'), ('FTP', 'FTP'), ('SFTP', 'SFTP'), ('SMTP', 'SMTP'), ('IMAP', 'IMAP'), ('POP3', 'POP3'), ('TELNET', 'Telnet'), ('SSH', 'SSH'), ('RDP', 'RDP'), ('WEBDAV', 'WebDAV')], max_length=10)),
                ('puerto', models.IntegerField(null=True)),
                ('url', models.TextField()),
                ('ip', models.GenericIPAddressField(null=True)),
                ('objetivo', models.CharField(choices=[('ILICITO', 'Contenido ilícito'), ('ECONOMIA', 'Economía'), ('INFRAESTRUCTURA', 'Infraestructura')], max_length=20, null=True)),
                ('metodo', models.CharField(choices=[('ENGANIO', 'Engaño: Phishing, Scam, etc...'), ('TECNICO', 'Técnico: Malware, exploit, etc...'), ('EVASION', 'Evasión: VPN, Proxies, etc...')], max_length=20, null=True)),
                ('impacto_legal', models.CharField(choices=[('GRAVE', 'Grave'), ('MODERADO', 'Moderado'), ('LEVE', 'Leve')], max_length=20, null=True)),
                ('descripcion', models.TextField(null=True)),
                ('fecha_deteccion', models.DateTimeField(auto_now_add=True)),
                ('ultima_acceso', models.DateTimeField(auto_now=True)),
                ('total_accesos', models.IntegerField(default=1)),
            ],
        ),
        migrations.CreateModel(
            name='Evidencia',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('metodo_deteccion', models.CharField(choices=[('FIRMA', 'Análisis de Firmas'), ('HEURISTICA', 'Heurística'), ('MACHINE_LEARNING', 'Machine Learning/IA'), ('REPUTACION', 'Análisis de Reputación'), ('SANDBOX', 'Sandboxing'), ('HEADERS', 'Análisis de Headers HTTP'), ('SSL', 'Detección de Certificados SSL'), ('SCRAPING', 'Web Scraping'), ('DNS', 'DNS Analysis'), ('HONEYPOT', 'HoneyPot')], max_length=20)),
                ('descripcion', models.TextField(blank=True)),
                ('archivo', models.FileField(blank=True, help_text='Formatos permitidos: imágenes, documentos, archivos de red y comprimidos', max_length=500, null=True, storage=Lista_negra.storage_backends.CustomStorage(), upload_to='evidencias/%Y/%m/%d/', validators=[django.core.validators.FileExtensionValidator(allowed_extensions=['png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'log', 'json', 'xml', 'pcap', 'har', 'zip', 'rar', 'tar', 'gz', 'csv', 'xlsx', 'docx']), Lista_negra.validators.validate_file_size], verbose_name='Archivo de evidencia')),
                ('datos_tecnicos', models.JSONField(blank=True, default=dict)),
                ('hash_sha256', models.CharField(blank=True, max_length=64)),
                ('fecha_creacion', models.DateTimeField(auto_now_add=True)),
                ('fecha_actualizacion', models.DateTimeField(auto_now=True)),
                ('url_maliciosa', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='evidencias', to='Lista_negra.url_maliciosa')),
            ],
            options={
                'verbose_name': 'Evidencia Técnica',
                'verbose_name_plural': 'Evidencias Técnicas',
                'ordering': ['-fecha_creacion'],
            },
        ),
        migrations.CreateModel(
            name='Acceso',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fecha', models.DateTimeField(auto_now_add=True)),
                ('entidad', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='Administrador.entidad')),
                ('url', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Lista_negra.url_maliciosa')),
            ],
        ),
    ]
