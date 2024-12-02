from django.db import models

# Create your models here
class Doctor(models.Model):
    name = models.CharField(max_length=100)
    department = models.CharField(max_length=100)
    contact = models.CharField(max_length=15)
    status = models.CharField(max_length=20)  # e.g., "On Hold", "Permanent"
 
    def __str__(self):
        return self.name
 
class Patient(models.Model):
    name = models.CharField(max_length=100)
    symptoms = models.TextField()
    contact = models.CharField(max_length=15)
    address = models.CharField(max_length=200)
    status = models.CharField(max_length=20)  # e.g., "On Hold", "Admitted"
 
    def __str__(self):
        return self.name
    
class Appointment(models.Model):
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE)
    appointment_date = models.DateTimeField()
    status = models.CharField(max_length=20, choices=[('scheduled', 'Scheduled'), ('completed', 'Completed'), ('cancelled', 'Cancelled')])
 
    def __str__(self):
        return f"Appointment with {self.doctor.name} for {self.patient.name} on {self.appointment_date}"

class WellnessTransaction(models.Model):
    CATEGORY_CHOICES = [
        ('Diet', 'Diet'),
        ('Fitness', 'Fitness'),
        ('Medical', 'Medical'),
        ('Other', 'Other'),
    ]
 
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    description = models.TextField()
    date = models.DateField()
 
    def __str__(self):
        return f"{self.category}: {self.amount} on {self.date}"
    


 
