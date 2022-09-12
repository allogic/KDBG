#include <kc_core.h>
#include <kc_debug.h>

#include <views/kc_toolbar.h>
#include <views/kc_process.h>
#include <views/kc_process_image.h>
#include <views/kc_kernel_image.h>
#include <views/kc_header.h>
#include <views/kc_disassembler.h>
#include <views/kc_memory.h>
#include <views/kc_scanner.h>

#include <glad/glad.h>

#include <glfw/glfw3.h>

#include <imgui/imgui.h>
#include <imgui/imgui_impl_glfw.h>
#include <imgui/imgui_impl_opengl3.h>

///////////////////////////////////////////////////////////
// Globals
///////////////////////////////////////////////////////////

HANDLE g_driverHandle = INVALID_HANDLE_VALUE;

kdbg::Toolbar g_toolbar = {};
kdbg::Process g_process = {};
kdbg::ProcessImage g_processImage = {};
kdbg::KernelImage g_kernelImage = {};
kdbg::Header g_header = {};
kdbg::Disassembler g_disassembler = {};
kdbg::Memory g_memory = {};
kdbg::Scanner g_scanner = {};

///////////////////////////////////////////////////////////
// Entry point
///////////////////////////////////////////////////////////

int32_t main(int32_t argc, wchar_t argv[])
{
  // Connect communication device
  g_driverHandle = CreateFileA("\\\\.\\KMOD", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if (g_driverHandle != INVALID_HANDLE_VALUE)
  {
    // Initialize glfw
    if (glfwInit())
    {
      // Setup glfw
      glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 4);
      glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
      glfwWindowHint(GLFW_SAMPLES, 0);
      glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
      glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

      // Window dimensions
      int32_t width = 1920;
      int32_t height = 1080;

      // Create window
      GLFWwindow* window = glfwCreateWindow(width, height, "", nullptr, nullptr);
      if (window)
      {
        // Make context current
        glfwMakeContextCurrent(window);

        // Load gl
        if (gladLoadGL())
        {
          // Set swap interval
          glfwSwapInterval(0);

          // Check imgui version
          IMGUI_CHECKVERSION();

          // Setup imgui
          ImGuiContext* imGuiContext = ImGui::CreateContext();
          ImGuiIO& io = ImGui::GetIO();
          io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
          io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
          io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

          // Setup imgui style
          ImGui::StyleColorsDark();
          ImGuiStyle& style = ImGui::GetStyle();
          if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
          {
            style.WindowRounding = 0.0f;
            style.FrameBorderSize = 0.0f;
            style.Colors[ImGuiCol_WindowBg].w = 1.0f;
          }

          // Init imgui
          bool imguiGLFWInitialized = ImGui_ImplGlfw_InitForOpenGL(window, true);
          bool imguiOGLinitialized = ImGui_ImplOpenGL3_Init("#version 400 core");
          if (imGuiContext && imguiGLFWInitialized && imguiOGLinitialized)
          {
            // Setup time
            float time = 0.0f;
            float timePrev = 0.0f;
            float timeDelta = 0.0f;

            while (glfwWindowShouldClose(window) == FALSE)
            {
              // Compute time
              time = (float)glfwGetTime();
              timeDelta = time - timePrev;
              timePrev = time;

              // Set clear color
              glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
              glClear(GL_COLOR_BUFFER_BIT);

              // Set viewport
              glViewport(0, 0, width, height);

              // Begin imgui frame
              ImGui_ImplOpenGL3_NewFrame();
              ImGui_ImplGlfw_NewFrame();
              ImGui::NewFrame();
              ImGui::DockSpaceOverViewport(ImGui::GetMainViewport());

              // Render views
              g_toolbar.Draw(time);
              if (g_toolbar.IsProcessWindowOpen()) g_process.Draw(time);
              if (g_toolbar.IsProcessImageWindowOpen()) g_processImage.Draw(time);
              if (g_toolbar.IsKernelImageWindowOpen()) g_kernelImage.Draw(time);
              if (g_toolbar.IsHeaderWindowOpen()) g_header.Draw(time);
              if (g_toolbar.IsDisassemblerWindowOpen()) g_disassembler.Draw(time);
              if (g_toolbar.IsMemoryWindowOpen()) g_memory.Draw(time);
              if (g_toolbar.IsScannerWindowOpen()) g_scanner.Draw(time);

              // End imgui frame
              ImGui::Render();
              ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
              ImGui::UpdatePlatformWindows();
              ImGui::RenderPlatformWindowsDefault();

              // Make context current
              glfwMakeContextCurrent(window);

              // Swap buffers
              glfwSwapBuffers(window);

              // Poll events
              glfwPollEvents();
            }

            // Terminate imgui
            ImGui_ImplOpenGL3_Shutdown();
            ImGui_ImplGlfw_Shutdown();
            ImGui::DestroyContext();
          }
          else
          {
            KD_LOG("Failed initializing imgui\n");
          }
        }
        else
        {
          KD_LOG("Failed loading GL\n");
        }

        // Terminate glfw
        glfwDestroyWindow(window);
        glfwTerminate();
      }
      else
      {
        KD_LOG("Failed creating window\n");
      }
    }
    else
    {
      KD_LOG("Failed initializing GLFW\n");
    }

    // Close driver
    CloseHandle(g_driverHandle);
  }
  else
  {
    KD_LOG("Failed connecting to kernel\n");
  }

  return 0;
}