from django.shortcuts import render
from django.views import View
from Index import views as Index_views
# Create your views here.
class Lista_negra(View):
    @staticmethod
    def Notification(self,request,Error=None,Success=None):
        if request.user.is_authenticated:
            return render(request,'dashboard/lista_negra/lista_negra.html',{
                'Error':Error,'Success':Success
            })
        return Index_views.redirigir_usuario(request=request)
    
    def get(self,request):
        if request.user.is_authenticated:
            return render(request,'dashboard/lista_negra/lista_negra.html')
        return Index_views.redirigir_usuario(request=request)
    
    def post(self,request):
        if request.user.is_authenticated:
            return render(request,'dashboard/lista_negra/lista_negra.html')
        return Index_views.redirigir_usuario(request=request)
    